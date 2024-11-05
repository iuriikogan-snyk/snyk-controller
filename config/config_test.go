package main

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/golang/mock/gomock"
)

// MockSecretsManager is a mock implementation of the SecretsManager interface
type MockSecretsManager struct {
	ctrl     *gomock.Controller
	recorder *MockSecretsManagerMockRecorder
}

// MockSecretsManagerMockRecorder is the mock recorder for MockSecretsManager
type MockSecretsManagerMockRecorder struct {
	mock *MockSecretsManager
}

// NEWMockSecretsManager creates a new mock instance
func NEWMockSecretsManager(ctrl *gomock.Controller) *MockSecretsManager {
	mock := &MockSecretsManager{ctrl: ctrl}
	mock.recorder = &MockSecretsManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockSecretsManager) EXPECT() *MockSecretsManagerMockRecorder {
	return m.recorder
}

// GetSecret mocks base method
func (m *MockSecretsManager) GetSecret(name string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSecret", name)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSecret indicates an expected call of GetSecret
func (mr *MockSecretsManagerMockRecorder) GetSecret(name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSecret", reflect.TypeOf((*MockSecretsManager)(nil).GetSecret), name)
}

func TestLoadConfig(t *testing.T) {
	t.Run("Loads config from environment variables and secrets manager", func(t *testing.T) {
		os.Setenv("LOG_LEVEL", "DEBUG")
		os.Setenv("SNYK_ORG_ID", "test-org-id")
		os.Setenv("SNYK_API_ENDPOINT", "https://api.snyk.io/v1")
		os.Setenv("REGISTRY_URL", "https://my.registry.io")
		os.Setenv("SECRETS_PROVIDER", "aws")
		os.Setenv("AWS_ROLE_ARN", "test-role-arn")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockSecretsManager := NEWMockSecretsManager(ctrl)
		mockSecretsManager.EXPECT().GetSecret("SNYK_TOKEN").Return("test-snyk-token", nil)
		mockSecretsManager.EXPECT().GetSecret("REGISTRY_USERNAME").Return("test-registry-username", nil)
		mockSecretsManager.EXPECT().GetSecret("REGISTRY_PASSWORD").Return("test-registry-password", nil)

		// Replace the actual LoadSecretsManager function with our mock
		oldLoadSecretsManager := LoadSecretsManager
		defer func() { LoadSecretsManager = oldLoadSecretsManager }()
		LoadSecretsManager = func() (SecretsManager, error) {
			return mockSecretsManager, nil
		}

		err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig() returned an error: %v", err)
		}

		if snykToken != "test-snyk-token" {
			t.Errorf("Expected snykToken to be 'test-snyk-token', got '%s'", snykToken)
		}

		if snykOrgID != "test-org-id" {
			t.Errorf("Expected snykOrgID to be 'test-org-id', got '%s'", snykOrgID)
		}

		if snykApiEndpoint != "https://api.snyk.io/v1" {
			t.Errorf("Expected snykApiEndpoint to be 'https://api.snyk.io/v1', got '%s'", snykApiEndpoint)
		}

		if registryUsername != "test-registry-username" {
			t.Errorf("Expected registryUsername to be 'test-registry-username', got '%s'", registryUsername)
		}

		if registryPassword != "test-registry-password" {
			t.Errorf("Expected registryPassword to be 'test-registry-password', got '%s'", registryPassword)
		}

		if registryUrl != "https://my.registry.io" {
			t.Errorf("Expected registryUrl to be 'https://my.registry.io', got '%s'", registryUrl)
		}
	})

	t.Run("Returns error if secrets manager returns an error", func(t *testing.T) {
		os.Setenv("SECRETS_PROVIDER", "aws")
		os.Setenv("AWS_ROLE_ARN", "test-role-arn")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockSecretsManager := NEWMockSecretsManager(ctrl)
		mockSecretsManager.EXPECT().GetSecret("SNYK_TOKEN").Return("", fmt.Errorf("failed to get secret"))

		// Replace the actual LoadSecretsManager function with our mock
		oldLoadSecretsManager := LoadSecretsManager
		defer func() { LoadSecretsManager = oldLoadSecretsManager }()
		LoadSecretsManager = func() (SecretsManager, error) {
			return mockSecretsManager, nil
		}

		err := LoadConfig()
		if err == nil {
			t.Fatal("LoadConfig() did not return an error")
		}
	})
}

func TestAwsSecretsManager_GetSecret(t *testing.T) {
	t.Run("Successfully retrieves secret from AWS Secrets Manager", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockSecretsManagerClient := secretsmanager.New(nil)
		mockSecretsManagerClient.GetSecretValueWithContext = func(aws.Context, *secretsmanager.GetSecretValueInput, ...request.Option) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("test-secret-value"),
			}, nil
		}

		awsSecretsManager := &AwsSecretsManager{
			sm: mockSecretsManagerClient,
		}

		secret, err := awsSecretsManager.GetSecret("test-secret-name")
		if err != nil {
			t.Fatalf("GetSecret() returned an error: %v", err)
		}

		if secret != "test-secret-value" {
			t.Errorf("Expected secret to be 'test-secret-value', got '%s'", secret)
		}
	})

	t.Run("Returns error if AWS Secrets Manager returns an error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockSecretsManagerClient := secretsmanager.New(nil)
		mockSecretsManagerClient.GetSecretValueWithContext = func(aws.Context, *secretsmanager.GetSecretValueInput, ...request.Option) (*secretsmanager.GetSecretValueOutput, error) {
			return nil, awserr.New(secretsmanager.ErrCodeResourceNotFoundException, "secret not found", nil)
		}

		awsSecretsManager := &AwsSecretsManager{
			sm: mockSecretsManagerClient,
		}

		_, err := awsSecretsManager.GetSecret("non-existent-secret")
		if err == nil {
			t.Fatal("GetSecret() did not return an error")
		}

		if !strings.Contains(err.Error(), "secret not found") {
			t.Errorf("Expected error message to contain 'secret not found', got '%s'", err.Error())
		}
	})
}
func TestAzureSecretsManager_GetSecret(t *testing.T) {
	t.Run("Successfully retrieves secret from Azure Key Vault", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := azsecrets.NewClient(nil)
		mockClient.GetSecret = func(ctx context.Context, name string, options *azsecrets.GetSecretOptions) (*azsecrets.GetSecretResponse, error) {
			return &azsecrets.GetSecretResponse{
				Value: aws.String("test-secret-value"),
			}, nil
		}

		azureSecretsManager := &AzureSecretsManager{
			client: mockClient,
		}

		secret, err := azureSecretsManager.GetSecret("test-secret-name")
		if err != nil {
			t.Fatalf("GetSecret() returned an error: %v", err)
		}

		if secret != "test-secret-value" {
			t.Errorf("Expected secret to be 'test-secret-value', got '%s'", secret)
		}
	})

	t.Run("Returns error if Azure Key Vault returns an error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := azsecrets.NewClient(nil)
		mockClient.GetSecret = func(ctx context.Context, name string, options *azsecrets.GetSecretOptions) (*azsecrets.GetSecretResponse, error) {
			return nil, fmt.Errorf("secret not found")
		}

		azureSecretsManager := &AzureSecretsManager{
			client: mockClient,
		}

		_, err := azureSecretsManager.GetSecret("non-existent-secret")
		if err == nil {
			t.Fatal("GetSecret() did not return an error")
		}

		if !strings.Contains(err.Error(), "secret not found") {
			t.Errorf("Expected error message to contain 'secret not found', got '%s'", err.Error())
		}
	})
}

func TestK8sSecretsManager_GetSecret(t *testing.T) {
	t.Run("Successfully retrieves secret from environment variables", func(t *