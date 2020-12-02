$appName = "Test FBA SSO App"
$ServerHostName = "fba.uiserver.com"

$User = Read-Host  "Enter your Azure tenant adminstrator login name: "
$PlainPassword = Read-Host -assecurestring "Please enter '$User' password"
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PlainPassword))
$serverIpAddress = Read-Host  "Enter the private ip adreess for Forcepoint backend server: "
$internalUrl = "https://$ServerHostName/"

$oldPolicy = Get-ExecutionPolicy
$oldErrorAction = $ErrorActionPreference
Set-ExecutionPolicy RemoteSigned -Force
$ErrorActionPreference = 'Stop'
function Show-Menu
{
    param (
        [string]$Title = 'Forecepoint - Azure Application Proxy'
    )
    Clear-Host
    Write-Host "================ $Title ================"

    Write-Host "1: Press '1' to install The Azure Application Proxy Connector."
    Write-Host "2: Press '2' to create and configure Azure app registrations."
    Write-Host "3: Press '3' All above"
    Write-Host "Q: Press 'Q' to quit."
}


Write-host "Reading Powershell version"
$version = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release)
$versionnum = $version.release
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

If ($versionnum -lt "461814"){
    Write-host "Examining the .NET framework version to support newer versions of Azure cmdlets, please wait" -Backgroundcolor Yellow -Foregroundcolor Black
    #How we determine build https://github.com/dotnet/docs/blob/master/docs/framework/migration-guide/how-to-determine-which-versions-are-installed.md
    Write-host ".NET Framework 4.7.2 not installed, please allow for install & reboot" -BackgroundColor Yellow -ForegroundColor Black
    $temp = "C:\temp\download"
    $installername = "NDP472-KB4054530-x86-x64-AllOS-ENU.exe"
    $installerpath = $temp + "\" +  $installername

    New-Item -Path $temp -ItemType Directory -Verbose
    Write-host "Installing the updated .NET framework to support newer versions of Azure cmdlets. This may reboot so please relaunch the script afterwards." -Backgroundcolor Yellow -Foregroundcolor Black
    #found the installer http://forums.wsusoffline.net/viewtopic.php?f=6&t=7905&sid=1b70c08d201f1997004449c28bc3c348&start=10
    $url = “https://download.microsoft.com/download/6/E/4/6E48E8AB-DC00-419E-9704-06DD46E5F81D/NDP472-KB4054530-x86-x64-AllOS-ENU.exe” #download path for SQLLite Tools
    Start-BitsTransfer -Source $url -Destination $temp

    $invokecmd = “cmd.exe /c $installerpath /q”
    Invoke-Expression $invokecmd
}

do
{
    Show-Menu –Title 'Azure Application Proxy Deployment'
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
        '1' {
            Write-host "Downloading the Application Proxy Service Connector...." -BackgroundColor Yellow -ForegroundColor Black

            $url = 'https://download.msappproxy.net/subscription/d3c8b69d-6bf7-42be-a529-3fe9c2e70c90/connector/DownloadConnectorInstaller'
            Invoke-WebRequest -Uri $url -OutFile ~\AADApplicationProxyConnectorInstaller.exe
            Start-Sleep -Seconds 3
            Write-host "Installing the Application Proxy Service Connector, please wait.." -BackgroundColor Green -ForegroundColor Black
            ~\AADApplicationProxyConnectorInstaller.exe REGISTERCONNECTOR='false' /q
            Start-Sleep -Seconds 40
            $SecurePassword = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force
            $cred = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $User, $SecurePassword
            cd 'C:\Program Files\Microsoft AAD App Proxy Connector'
            Write-host "Register the Application Proxy Service Connector with your Azure Tenant.." -BackgroundColor Yellow -ForegroundColor Blac
            .\RegisterConnector.ps1 -modulePath 'C:\Program Files\Microsoft AAD App Proxy Connector\Modules\' -moduleName 'AppProxyPSModule' -Authenticationmode Credentials -Usercredentials $cred -Feature ApplicationProxy
            Start-Sleep -Seconds 3
            cd ~
        }
        '2' {
            If (!(Get-module "AzureAd")) {
                Write-host "Downloading the Azure Powershell module" -BackgroundColor Yellow -ForegroundColor Black
                Install-PackageProvider -Name NuGet -RequiredVersion 2.8.5.201 -Force
                Install-Module AzureAD -Force
                Write-host "Loading the Azure Powershell module, please wait" -BackgroundColor Green -ForegroundColor Black
                Import-Module AzureAD} Else {
                Write-host "Loading the Azure Powershell module, please wait" -BackgroundColor Green -ForegroundColor Black
                Import-Module AzureAD}
            If (!(Get-module "Carbon")) {
                Write-host "Downloading the Carbon Powershell module" -BackgroundColor Yellow -ForegroundColor Black
                Install-Module -Name 'Carbon' -AllowClobber -Force
                Write-host "Loading the Carbon Powershell module, please wait" -BackgroundColor Green -ForegroundColor Black
                Import-Module 'Carbon'} Else {
                Write-host "Loading the Azure Carbon module, please wait" -BackgroundColor Green -ForegroundColor Black
                Import-Module 'Carbon'}

            $SecurePassword = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force
            $cred = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $User, $SecurePassword
            Connect-AzureAD -Credential $cred

            Write-host "Gathering tenant information, please wait" -BackgroundColor Yellow -ForegroundColor Black
            $mytenant = Get-AzureADTenantDetail
            $mytenantdomain = ($mytenant.VerifiedDomains).name
            $mytenantdomain = [string]$mytenantdomain
            $domainParts = $mytenantdomain.Split(".")
            $mytenantdomain = $domainParts[0]
            $mytenantid = $mytenant.ObjectID
            $schemaName = $appName
            if ($schemaName -match " ") {$schemaName = $schemaName -replace " ", ""}

            $externalUrl2 = "https://" + $schemaName + "-" + $mytenantdomain + ".msappproxy.net/"
            $externalUrl2 = $externalUrl2.ToLower()
            $internalUrl = $internalUrl.ToLower()
            Write-host "Create an Azure Application Proxy Application with name: "$appName -BackgroundColor Green -ForegroundColor Black

            New-AzureADApplicationProxyApplication -DisplayName $appName -ExternalUrl $externalUrl2 -InternalUrl $internalUrl -ApplicationServerTimeout Long
            Start-Sleep -Seconds 20
            Write-host "Adding Application Proxy Service Connector to" $appName "group" -BackgroundColor Yellow -ForegroundColor Black
            $groupExists = Get-AzureADApplicationProxyConnectorGroup |  ?{$_.name -like $appName}
            if (!$groupExists) {
                Write-host "Adding Application Proxy Service Connector to" $appName "group" -BackgroundColor Green -ForegroundColor Black
                $newGroup = New-AzureADApplicationProxyConnectorGroup -Name $appName
                $groupId = $newGroup.Id
            }else{
                $groupId = $groupExists.Id
            }

            $connector = Get-AzureADApplicationProxyConnector |  ?{$_.MachineName -like $env:computername}
            if (!$connector) {
                Write-host "Couldn't find an Application Proxy Connector on Azure which mactch your computer name:" $env:computername -BackgroundColor Red -ForegroundColor Black
            }else {
                $connectorId = $connector.Id
                Set-AzureADApplicationProxyConnector -Id $connectorId -ConnectorGroupId $groupId
            }
            Set-AzureADApplicationProxyApplication -ObjectId $azureAppObj -ConnectorGroupId $groupId
            Set-HostsEntry -IPAddress $serverIpAddress -HostName $ServerHostName

        }
        '3' {
            If (!(Get-module "AzureAd")) {
                Write-host "Downloading the Azure Powershell module" -BackgroundColor Yellow -ForegroundColor Black
                Install-PackageProvider -Name NuGet -RequiredVersion 2.8.5.201 -Force
                Install-Module AzureAD -Force
                Write-host "Loading the Azure Powershell module, please wait" -BackgroundColor Green -ForegroundColor Black
                Import-Module AzureAD} Else {
                Write-host "Loading the Azure Powershell module, please wait" -BackgroundColor Green -ForegroundColor Black
                Import-Module AzureAD}
            If (!(Get-module "Carbon")) {
                Write-host "Downloading the Carbon Powershell module" -BackgroundColor Yellow -ForegroundColor Black
                Install-Module -Name 'Carbon' -AllowClobber -Force
                Write-host "Loading the Carbon Powershell module, please wait" -BackgroundColor Green -ForegroundColor Black
                Import-Module 'Carbon'} Else {
                Write-host "Loading the Azure Carbon module, please wait" -BackgroundColor Green -ForegroundColor Black
                Import-Module 'Carbon'}


            Write-host "Downloading the Application Proxy Service Connector...." -BackgroundColor Yellow -ForegroundColor Black

            $url = 'https://download.msappproxy.net/subscription/d3c8b69d-6bf7-42be-a529-3fe9c2e70c90/connector/DownloadConnectorInstaller'
            Invoke-WebRequest -Uri $url -OutFile ~\AADApplicationProxyConnectorInstaller.exe
            Start-Sleep -Seconds 3
            Write-host "Installing the Application Proxy Service Connector, please wait.." -BackgroundColor Green -ForegroundColor Black
            ~\AADApplicationProxyConnectorInstaller.exe REGISTERCONNECTOR='false' /q
            Start-Sleep -Seconds 40
            $SecurePassword = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force
            $cred = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $User, $SecurePassword
            cd 'C:\Program Files\Microsoft AAD App Proxy Connector'
            Write-host "Register the Application Proxy Service Connector with your Azure Tenant.." -BackgroundColor Yellow -ForegroundColor Blac
            .\RegisterConnector.ps1 -modulePath 'C:\Program Files\Microsoft AAD App Proxy Connector\Modules\' -moduleName 'AppProxyPSModule' -Authenticationmode Credentials -Usercredentials $cred -Feature ApplicationProxy
            Start-Sleep -Seconds 3
            cd ~

            $SecurePassword = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force
            $cred = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $User, $SecurePassword
            Connect-AzureAD -Credential $cred

            Write-host "Gathering tenant information, please wait" -BackgroundColor Yellow -ForegroundColor Black
            $mytenant = Get-AzureADTenantDetail
            $mytenantdomain = ($mytenant.VerifiedDomains).name
            $mytenantdomain = [string]$mytenantdomain
            $domainParts = $mytenantdomain.Split(".")
            $mytenantdomain = $domainParts[0]
            $mytenantid = $mytenant.ObjectID
            $schemaName = $appName
            if ($schemaName -match " ") {$schemaName = $schemaName -replace " ", ""}
            $externalUrl3 = "https://" + $schemaName + "-" + $mytenantdomain + ".msappproxy.net/"
            $externalUrl3 = $externalUrl3.ToLower()
            $internalUrl = $internalUrl.ToLower()
            Write-host "Create an Azure Application Proxy Application with name: "$appName -BackgroundColor Green -ForegroundColor Black

            New-AzureADApplicationProxyApplication -DisplayName $appName -ExternalUrl $externalUrl3 -InternalUrl $internalUrl -ApplicationServerTimeout Long
            Start-Sleep -Seconds 20
            Write-host "Adding Application Proxy Service Connector to" $appName "group" -BackgroundColor Yellow -ForegroundColor Black
            $groupExists = Get-AzureADApplicationProxyConnectorGroup |  ?{$_.name -like $appName}
            if (!$groupExists) {
                Write-host "Adding Application Proxy Service Connector to" $appName "group" -BackgroundColor Green -ForegroundColor Black
                $newGroup = New-AzureADApplicationProxyConnectorGroup -Name $appName
                $groupId = $newGroup.Id
            }else{
                $groupId = $groupExists.Id
            }

            $connector = Get-AzureADApplicationProxyConnector |  ?{$_.MachineName -like $env:computername}
            if (!$connector) {
                Write-host "Couldn't find an Application Proxy Connector on Azure which mactch your computer name:" $env:computername -BackgroundColor Red -ForegroundColor Black
            }else {
                $connectorId = $connector.Id
                Set-AzureADApplicationProxyConnector -Id $connectorId -ConnectorGroupId $groupId
            }
            Set-AzureADApplicationProxyApplication -ObjectId $azureAppObj -ConnectorGroupId $groupId
            Set-HostsEntry -IPAddress $serverIpAddress -HostName $ServerHostName
        }
    }
    pause
}
until ($selection -eq 'q')
Set-ExecutionPolicy $oldPolicy -Force
$ErrorActionPreference = $oldErrorAction









