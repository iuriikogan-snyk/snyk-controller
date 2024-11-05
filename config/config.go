package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

type SecretsManager interface {
	GetSecret(name string) (string, error)
}

type AwsSecretsManager struct {
	sm *secretsmanager.SecretsManager
}

func NewAwsSecretsManager() (*AwsSecretsManager, error) {
	sess := session.Must(session.NewSession())
	roleArn := os.Getenv("AWS_ROLE_ARN")
	if roleArn == "" {
		return nil, fmt.Errorf("AWS_ROLE_ARN is required for AWS authentication")
	}
	creds := stscreds.NewCredentials(sess, roleArn)
	sm := secretsmanager.New(sess, &aws.Config{Credentials: creds})
	return &AwsSecretsManager{sm: sm}, nil
}

func (a *AwsSecretsManager) GetSecret(name string) (string, error) {
	output, err := a.sm.GetSecretValue(&secretsmanager.GetSecretValueInput{SecretId: aws.String(name)})
	if err != nil {
		return "", err
	}
	return *output.SecretString, nil
}

type AzureSecretsManager struct {
	client *azsecrets.Client
}

func NewAzureSecretsManager() (*AzureSecretsManager, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("Azure credential initialization failed: %w", err)
	}
	vaultURL := os.Getenv("AZURE_VAULT_URL")
	if vaultURL == "" {
		return nil, fmt.Errorf("AZURE_VAULT_URL is required for Azure Key Vault")
	}
	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, err
	}
	return &AzureSecretsManager{client: client}, nil
}

func (az *AzureSecretsManager) GetSecret(name string) (string, error) {
	resp, err := az.client.GetSecret(ctx, name, nil)
	if err != nil {
		return "", err
	}
	return *resp.Value, nil
}

func LoadSecretsManager() (SecretsManager, error) {
	switch os.Getenv("SECRETS_PROVIDER") {
	case "aws":
		return NewAwsSecretsManager()
	case "azure":
		return NewAzureSecretsManager()
	default:
		return nil, fmt.Errorf("unsupported SECRETS_PROVIDER: %s", os.Getenv("SECRETS_PROVIDER"))
	}
}

var (
	snykToken        string
	snykOrgID        string
	registryUsername string
	registryPassword string
	registryUrl      string
	logger           *slog.Logger
)

func LoadConfig() error {
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "INFO"
	}
	logger = slog.New(slog.NewTextHandler(os.Stdout, slog.LevelFromString(logLevel)))

	snykOrgID = os.Getenv("SNYK_ORG_ID")
	registryUrl = os.Getenv("REGISTRY_URL")
	if snykOrgID == "" {
		logger.Warn("SNYK_ORG_ID is not set; some features may be unavailable")
	}
	if registryUrl == "" {
		logger.Warn("REGISTRY_URL is not set; registry interactions may be affected")
	}

	secretsManager, err := LoadSecretsManager()
	if err != nil {
		logger.Error("Failed to initialize secrets manager", slog.Any("error", err))
		return err
	}

	snykToken, err = secretsManager.GetSecret("SNYK_TOKEN")
	if err != nil {
		logger.Error("Failed to retrieve SNYK_TOKEN from secrets manager", slog.Any("error", err))
		return err
	}

	registryUsername, err = secretsManager.GetSecret("REGISTRY_USERNAME")
	if err != nil {
		logger.Warn("Failed to retrieve REGISTRY_USERNAME from secrets manager; registry access may be limited")
	}

	registryPassword, err = secretsManager.GetSecret("REGISTRY_PASSWORD")
	if err != nil {
		logger.Warn("Failed to retrieve REGISTRY_PASSWORD from secrets manager; registry access may be limited")
	}

	logger.Info("Configuration loaded successfully")
	return nil
}

func main() {
	if err := LoadConfig(); err != nil {
		logger.Error("Configuration failed to load", slog.Any("error", err))
		return
	}
}
