package cmd

import (
	"fmt"
	"github.cicd.cloud.fpdev.io/BD/fp-fba-azure-sso/azurecli"
	"github.cicd.cloud.fpdev.io/BD/fp-fba-azure-sso/lib"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"

	"github.com/spf13/viper"
)

var (
	cfgFile       string
	DBInstance    *lib.Database
	AzureInstance *azurecli.AzureCLI
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "fp-fba-azure-sso",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file config.yml)")
	if err := rootCmd.MarkPersistentFlagRequired("config"); err != nil {
		logrus.Fatal(err)
	}

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.SetDefault("POSTGRES_HOST", "")
	viper.SetDefault("POSTGRES_PORT", 5432)
	viper.SetDefault("POSTGRES_USER_NAME", "")
	viper.SetDefault("POSTGRES_DATABASE_NAME", "")
	viper.SetDefault("AZURE_ADMIN_LOGIN_PASSWORD", "")
	viper.SetDefault("AZURE_ADMIN_LOGIN_NAME", "")
	viper.SetDefault("AZURE_APPLICATION_NAME", "")
	viper.SetDefault("USERS_SYNC_TIME_IN_MINUTES", 3)
	viper.SetDefault("DEFAULT_FBA_PASSWORD", "ChangeME")
	viper.SetDefault("SSO_CONFIG_SCRIPT_PATH", "")
	viper.SetDefault("POSTGRES_DATABASE_PASSWORD", "")

	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	}
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
	}
	if cfgFile == "" {
		logrus.Fatal("required flag(s) 'config'' not set")
	}
	db, err := lib.NewDatabase()
	if err != nil {
		logrus.Fatal(err)
	}
	DBInstance = db
	AzureInstance = &azurecli.AzureCLI{}
}
