package azurecli

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"github.cicd.cloud.fpdev.io/BD/fp-fba-azure-sso/lib"
	errorWrapper "github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
)

var (
	ErrBadFormatEmail = errors.New("invalid email format")
	regexPEmail       = `^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`
	SamlConfigured    = errors.New("SSO already Configured")
	NotLoadedYet      = errors.New("not loaded yet")
)

type AzureCLI struct {
	IsLogin bool
}

func (a *AzureCLI) IsAlreadyLogin() (string, bool) {
	c := "az account show --query user.name -o tsv"
	output, err := ExecuteCmd(c)
	if err != nil {
		if strings.Contains(err.Error(), "Please run 'az login' to setup account") {
			a.IsLogin = false
			return "", false
		}
	}
	a.IsLogin = true
	return strings.TrimSpace(output), true
}

// login to azure
func (a *AzureCLI) Login() error {
	_, isLogin := a.IsAlreadyLogin()

	if !isLogin {
		var stdout, stderr bytes.Buffer
		if viper.GetString("AZURE_ADMIN_LOGIN_NAME") == "" {
			username, err := ReadUserLoginName()
			if err != nil {
				logrus.Fatal(err)
			}
			viper.Set("AZURE_ADMIN_LOGIN_NAME", username)
		}
		if viper.GetString("AZURE_ADMIN_LOGIN_PASSWORD") == "" {
			fmt.Printf("Enter password for '%s' and press Enter: ",
				viper.GetString("AZURE_ADMIN_LOGIN_NAME"))
			bytePassword, err := terminal.ReadPassword(syscall.Stdin)
			if err != nil {
				return err
			}
			password := string(bytePassword)
			fmt.Println() // do not remove it
			if len(password) == 0 {
				return errors.New("please enter a valid password")
			}
			viper.Set("AZURE_ADMIN_LOGIN_PASSWORD", strings.TrimSpace(password))
		}
		//login to azure
		c1 := fmt.Sprintf("az login -u %s -p '%s'",
			viper.GetString("AZURE_ADMIN_LOGIN_NAME"),
			viper.GetString("AZURE_ADMIN_LOGIN_PASSWORD"))
		exe := exec.Command("sh", "-c", c1)
		exe.Stderr = &stderr
		exe.Stdout = &stdout
		err := exe.Run()
		errorResult := string(stderr.Bytes())
		if len(errorResult) != 0 {
			if strings.Contains(errorResult, "Error validating credentials due to invalid username or password") {
				return errors.New("error in validating credentials due to invalid username or password")
			}
			return errors.New(errorResult)
		}
		if err != nil {
			return errors.New("failed in executing the azure login command")
		}
		a.IsLogin = true
	}
	return nil
}

// azure logout
func (a *AzureCLI) Logout() error {
	exe := exec.Command("sh", "-c", "az logout")
	err := exe.Run()
	if err != nil {
		err = errorWrapper.Wrap(err, "Failed in executing the azure logout command")
		return err
	}
	a.IsLogin = false
	return nil
}

func (a *AzureCLI) GetAppAssignedUsers(appName string) ([]string, error) {
	var appUsers []string
	c := fmt.Sprintf("az ad sp list --display-name '%s' --query [].objectId -o tsv", appName)
	appId, err := ExecuteCmd(c)
	if err != nil {
		return nil, err
	}
	appId = strings.TrimSpace(appId)
	if appId == "" {
		return nil, errors.New("failed in reading the app id")
	}
	c = fmt.Sprintf("az rest --method GET --uri https://graph.microsoft.com/beta/servicePrincipals/%s/appRoleAssignedTo --query value[].principalId -o tsv", appId)
	output, err := ExecuteCmd(c)
	if err != nil {
		return nil, err
	}
	output = strings.TrimSpace(output)
	userIds := strings.Split(output, "\n")
	for _, user := range userIds {
		c = fmt.Sprintf("az ad user show --id %s --query userPrincipalName -o tsv", user)
		output, err := ExecuteCmd(c)
		if err != nil {
			return nil, err
		}
		output = strings.TrimSpace(output)
		appUsers = append(appUsers, output)
	}
	return appUsers, nil
}

func ExecuteCmd(cmd string) (string, error) {
	var stdout, stderr bytes.Buffer
	exe := exec.Command("sh", "-c", cmd)
	exe.Stderr = &stderr
	exe.Stdout = &stdout
	err := exe.Run()
	errorResult := string(stderr.Bytes())
	if len(errorResult) != 0 && !strings.Contains(errorResult, "deprecated") {
		return "", errors.New(errorResult)
	}
	if err != nil && !strings.Contains(errorResult, "deprecated") {
		return "", errors.New(fmt.Sprintf("failed in executing the azure command: %s", cmd))
	}
	output := string(stdout.Bytes())
	if len(output) != 0 {
		return strings.TrimSpace(output), nil
	}
	return "", nil
}

func (a *AzureCLI) GetAllAzureUsers() ([]string, error) {
	c := "az ad user list --query [].userPrincipalName -o tsv"
	output, err := ExecuteCmd(c)
	if err != nil {
		return nil, err
	}
	output = strings.TrimSpace(output)
	return strings.Split(output, "\n"), nil
}

func ReadUserLoginName() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Enter your Azure administrator's username: ")
		text, err := reader.ReadString('\n')
		if err != nil {
			return "", errorWrapper.Wrap(err, "failed in reading username from console")
		}
		text = strings.Replace(text, "\n", "", -1)
		isValidEmail, err := ValidateEmailAddress(text)
		if !isValidEmail {
			logrus.Error(err)
		} else {
			return text, nil
		}
	}
}

func ValidateEmailAddress(email string) (bool, error) {
	emailRegexp := regexp.MustCompile(regexPEmail)
	if !emailRegexp.MatchString(email) {
		return false, errorWrapper.Wrap(ErrBadFormatEmail, email)
	}
	return true, nil
}

func (a *AzureCLI) CreateGroup(name string, description string) error {
	nickname := strings.ReplaceAll(name, "FP-FBA Role: ", "")
	nickname = strings.ReplaceAll(nickname, "FP-FBA Status: ", "")
	nickname = strings.ToLower(nickname)
	nicknameP := strings.Split(nickname, " ")
	nickname = strings.Join(nicknameP, ".")
	c := fmt.Sprintf("az rest --method POST --uri https://graph.microsoft.com/v1.0/groups --body "+
		"'{\"description\": \"%s\",\"displayName\": \"%s\",\"mailEnabled\":"+
		" false,\"mailNickname\": \"%s\",\"securityEnabled\": true}'", description, name, nickname)
	_, err := ExecuteCmd(c)
	if err != nil {
		return err
	}
	return nil
}

func (a *AzureCLI) GetUsrName(email string) (string, error) {
	c := fmt.Sprintf("az ad user show --id '%s' --query '[givenName, surname]' -o tsv", email)
	output, err := ExecuteCmd(c)
	if err != nil {
		return "", err
	}

	if strings.Contains(strings.TrimSpace(output), "None") {
		emailp := strings.Split(email, "@")
		emailp = strings.Split(emailp[0], ".")
		name := strings.Join(emailp, " ")
		return strings.Title(name), nil
	}
	outputP := strings.Split(strings.TrimSpace(output), "\n")
	output = strings.Join(outputP, " ")
	return output, nil
}

func (a *AzureCLI) ConfigureSaml(appName string) error {
	c := fmt.Sprintf("az ad sp list --display-name '%s' --query  [].objectId -o tsv", appName)
	appId, err := ExecuteCmd(c)
	if err != nil {
		return errorWrapper.Wrap(err, "failed in reading the sp ID for application: "+appName)
	}
	appId = strings.TrimSpace(appId)
	c = fmt.Sprintf("az ad sp list --display-name '%s' --query  [].preferredSingleSignOnMode -o tsv", appName)
	output, err := ExecuteCmd(c)
	if err != nil {
		return errorWrapper.Wrap(err, "failed in reading preferredSingleSignOnMode for application: "+appName)

	}
	output = strings.TrimSpace(output)
	if output == "" {
		c = fmt.Sprintf("az ad sp update  --id %s --set preferredSingleSignOnMode=\"saml\"", appId)
		_, _ = ExecuteCmd(c)
		logrus.Info("Configuring SSO...")

	} else {
		return SamlConfigured
	}
	return nil
}

func (a *AzureCLI) UpdateRelyUrls(appName string) error {
	c := fmt.Sprintf("az ad app list --display-name '%s' --query [].replyUrls -o tsv", appName)
	replayUrl, err := ExecuteCmd(c)
	if err != nil {
		return errorWrapper.Wrap(err, "failed in reading replayUrls for application: "+appName)

	}
	replayUrl = strings.TrimSpace(replayUrl)
	replayUrls := strings.Split(replayUrl, "\n")
	replayUrl = strings.Join(replayUrls, " ")

	c = fmt.Sprintf("az ad app list --display-name '%s' --query  [].objectId -o tsv", appName)
	appId2, err := ExecuteCmd(c)
	if err != nil {
		return errorWrapper.Wrap(err, "failed in reading  ID for application: "+appName)

	}
	appId2 = strings.TrimSpace(appId2)
	c = fmt.Sprintf("az ad app update --id '%s' --reply-urls %s", appId2, replayUrl)
	_, err = ExecuteCmd(c)
	if err != nil {
		return errorWrapper.Wrap(err, "failed in setting replayUrls ID for application: "+appName)

	}
	return nil

}

func (a *AzureCLI) GetSamlBase64Cert(appName string) (string, error) {
	c := fmt.Sprintf("az ad sp list --display-name '%s' --query  [].appId -o tsv", appName)
	appId, err := ExecuteCmd(c)
	if err != nil {
		return "", errorWrapper.Wrap(err, "failed in reading the sp ID for application: "+appName)
	}
	c = "az account show --query tenantId -o tsv"
	tenantId, err := ExecuteCmd(c)
	if err != nil {
		return "", errorWrapper.Wrap(err, "failed in reading the tenant ID")
	}
	url := fmt.Sprintf("https://login.microsoftonline.com/%s/federationmetadata/2007-06/federationmetadata.xml?appid=%s", tenantId, appId)
	c = "az account get-access-token --resource https://batch.core.windows.net --query accessToken -o tsv"
	batchToken, err := ExecuteCmd(c)
	if err != nil {
		return "", errorWrapper.Wrap(err, "failed in batch token request")
	}
	bearer := "Bearer " + batchToken
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", errorWrapper.Wrap(err, "failed in creating new http request")
	}
	req.Header.Add("Authorization", bearer)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error on response.\n[ERRO] -", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errorWrapper.Wrap(err, "failed in reading SSO XML request")
	}
	var sso lib.SSO
	err = xml.Unmarshal(body, &sso)
	if err != nil {
		return "", errorWrapper.Wrap(err, "failed in unmarshalling XML file")
	}
	cert := sso.Sig.KeyInfo.X509Data.Cert
	if strings.HasSuffix(cert, "8rhcOtPsFgJuoJokGjvcUSR/6Eqd") {
		return cert, NotLoadedYet
	}
	return cert, nil
}

func (a *AzureCLI) GetTenantId() (string, error) {
	c := "az account show --query tenantId -o tsv"
	tenantId, err := ExecuteCmd(c)
	if err != nil {
		return "", errorWrapper.Wrap(err, "failed in reading the tenant ID")
	}
	return tenantId, nil
}

func (a *AzureCLI) CreateSsoConfig(appName, cert string) (string, error) {
	template := `module.exports = {
   samlEmailField: "nameID",
   entryPoint: "%s",
   issuer: "%s",
   cert: "%s"
}`
	ssoShellScript := `#!/bin/bash

echo '%s' > /usr/lib/node_modules/ro-ui/config/saml_config.js
sed -i '/^SSO_TYPE:/d' /usr/lib/node_modules/ro-ui/config/.env
echo "SSO_TYPE: 'saml'" >> /usr/lib/node_modules/ro-ui/config/.env
sed -i "/'@Destination': this.options.entryPoint,/d" /usr/lib/node_modules/ro-ui/node_modules/passport-saml/lib/passport-saml/saml.js
sed -i "/'@AssertionConsumerServiceURL': self.getCallbackUrl(req),/d" /usr/lib/node_modules/ro-ui/node_modules/passport-saml/lib/passport-saml/saml.js 
systemctl restart ro-ui
`
	tenantId, err := a.GetTenantId()
	if err != nil {
		return "", err
	}
	endpointUrl := fmt.Sprintf("https://login.microsoftonline.com/%s/saml2", tenantId)
	c := fmt.Sprintf("az ad sp list --display-name '%s' --query [].homepage -o tsv", appName)
	homepage, err := ExecuteCmd(c)
	if err != nil {
		return "", errorWrapper.Wrap(err, "failed in querying the homepage for application: "+appName)
	}
	ssoConfig := fmt.Sprintf(template, endpointUrl, homepage, cert)
	script := fmt.Sprintf(ssoShellScript, ssoConfig)
	return script, nil
}

func (a *AzureCLI) ValidateAzureGroups(groupName string) (bool, error) {
	c := fmt.Sprintf("az ad group list --display-name '%s' --query [].displayName", groupName)
	output, err := ExecuteCmd(c)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(output) == "[]" {
		return false, nil
	}
	return true, nil

}

func (a *AzureCLI) GetAllGroupsMembers(roles map[string]int, appUsers []string) (map[string][]string, error) {
	groupsMembers := make(map[string][]string)
	for role, _ := range roles {
		c := fmt.Sprintf("az ad group member list -g '%s' --query [].userPrincipalName -o tsv", role)
		output, err := ExecuteCmd(c)
		if err != nil {
			return nil, err
		}
		output = strings.TrimSpace(output)
		outputP := strings.Split(output, "\n")
		var outputTemp []string
		for _, u := range outputP {
			if u != "" && u != " " {
				if strings.Contains(u, "#EXT#@") {
					userParts := strings.Split(u, "#")
					u = strings.ReplaceAll(userParts[0], "_", "@")
				}
				outputTemp = append(outputTemp, u)
			}
		}
		outputP = outputTemp
		for _, user := range outputP {
			user = strings.TrimSpace(user)
			if user != "" && user != " " && StringInList(appUsers, user) {
				groupsMembers[role] = append(groupsMembers[role], user)
			}
		}
	}
	return groupsMembers, nil

}
func StringInList(list []string, element string) bool {
	for _, i := range list {
		if i == element {
			return true
		}
	}
	return false
}
