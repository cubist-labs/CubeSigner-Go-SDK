package test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	. "github.com/cubist-labs/cubesigner-go-sdk/client"
	"github.com/cubist-labs/cubesigner-go-sdk/models"
	. "github.com/cubist-labs/cubesigner-go-sdk/session"
	"github.com/cubist-labs/cubesigner-go-sdk/utils"
	"github.com/cubist-labs/cubesigner-go-sdk/utils/ref"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/require"
)

type awsTestingEnv struct {
	awsSessionManager *AwsSessionManager
	awsSecretManager  *AwsSecretManager
	sessionClient     *ApiClient
}

var awsTestEnv awsTestingEnv

// mockSecretsManagerClient is for testing with a mock secrets manager client
type mockSecretsManagerClient struct {
	secrets map[string]string
	SecretsManagerClientAPI
}

// mock implementations for SecretsManagerClientAPI
func (mockClient mockSecretsManagerClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	secretId := *params.SecretId
	secretString := mockClient.secrets[secretId]
	out := &secretsmanager.GetSecretValueOutput{
		ARN:          params.SecretId,
		SecretString: &secretString,
	}
	return out, nil
}

// mock implementation for SecretsManagerClientApi
func (mockClient mockSecretsManagerClient) DescribeSecret(ctx context.Context, params *secretsmanager.DescribeSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	out := &secretsmanager.DescribeSecretOutput{
		ARN:              params.SecretId,
		NextRotationDate: nil,
	}
	return out, nil
}

// mock implementation for SecretsManagerClientAPI
func (mockClient mockSecretsManagerClient) UpdateSecret(ctx context.Context, params *secretsmanager.UpdateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretOutput, error) {
	secretId := *params.SecretId
	secretString := *params.SecretString

	// update mock secret
	mockClient.secrets[secretId] = secretString

	return &secretsmanager.UpdateSecretOutput{
		ARN: &secretId,
	}, nil
}

const MAX_CACHE_LIFETIME_SECS = uint64(5)

func init() {
	// setup mock client for secrets manager
	mockClient := &mockSecretsManagerClient{
		secrets: make(map[string]string, 1),
	}
	// load initial valid session from file
	sessionFile, err := utils.GetDefaultSessionFilePath()
	if err != nil {
		panic(fmt.Errorf("INIT: Failed to get SessionFile %s: %s\n", sessionFile, err))
	}
	sessionData, err := GetSessionFromFile(sessionFile)
	if err != nil {
		panic(fmt.Errorf("INIT: Failed to get SessionData: %s\n", err))
	}

	// set secret arn for "test_token" secret
	mockSecretId := "test_token"

	// set initial session in secrets manager
	encodedStr, err := EncodeSessionBase64(sessionData)
	if err != nil {
		panic(fmt.Errorf("INIT: Failed to encode session data: %s\n", err))
	}
	mockClient.secrets[mockSecretId] = encodedStr

	// initialize manager with new secret Id
	cache_max_lifetime := MAX_CACHE_LIFETIME_SECS
	awsTestEnv.awsSessionManager, err = NewTestAwsSessionManager(mockSecretId, mockClient, &cache_max_lifetime)
	if err != nil {
		panic(fmt.Errorf("INIT: Failed to create Aws Session Manager: %s\n", err))
	}
	awsTestEnv.sessionClient, err = NewApiClient(awsTestEnv.awsSessionManager)
	if err != nil {
		panic(fmt.Errorf("INIT: Failed to create an ApiClient: %s\n", err))
	}

	// initialize aws secret manager
	awsTestEnv.awsSecretManager, err = NewTestAwsSecretManager(mockSecretId, mockClient)
	if err != nil {
		panic(fmt.Errorf("INIT: Failed to create Aws Secret Manager: %s\n", err))
	}
}

func TestSecretFetch(t *testing.T) {
	_, err := awsTestEnv.awsSessionManager.Token()
	require.Nil(t, err)

	// perform a simple call to ensure token works
	resp, err := awsTestEnv.sessionClient.AboutMe()
	require.Nil(t, err)

	// test user id is non-empty
	value := resp.UserId
	require.NotEqual(t, "", value)
}

func TestSecretManager(t *testing.T) {
	// create a new session that will be refreshed
	sessionResp, err := awsTestEnv.sessionClient.CreateSession("AwsSecretManagerTest", []models.Scope{"manage:*"}, nil)
	require.Nil(t, err)
	require.False(t, sessionResp.RequiresMfa())
	sessionData := sessionResp.ResponseData

	// create another mock secret for this test
	mockClient := &mockSecretsManagerClient{
		secrets: make(map[string]string, 1),
	}
	secretId := "test_token"
	encodedSessionData, err := EncodeSessionBase64(sessionData)
	require.Nil(t, err)
	mockClient.secrets[secretId] = encodedSessionData

	// manager and client to use this created session
	newManager, err := NewTestAwsSessionManager(secretId, mockClient, ref.Of(MAX_CACHE_LIFETIME_SECS))
	require.Nil(t, err)
	newClient, err := NewApiClient(newManager)
	require.Nil(t, err)
	// secret manager to refresh the session
	secretManager, err := NewTestAwsSecretManager(secretId, mockClient)
	require.Nil(t, err)

	// make a base-line call
	_, err = newClient.AboutMe()
	require.Nil(t, err)

	prevToken, err := newManager.Token()
	require.Nil(t, err)

	// refresh session unconditionally
	err = secretManager.Refresh()
	require.Nil(t, err)
	err = secretManager.Refresh()
	require.Nil(t, err)

	// attempt a call again. This should work.
	resp, err := newClient.AboutMe()
	require.Nil(t, err)
	require.NotEqual(t, "", resp.UserId)

	// test token changed
	currToken, err := newManager.Token()
	require.Nil(t, err)
	require.NotEqual(t, currToken, prevToken)
}

func TestAwsConcurrentCalls(t *testing.T) {
	var wg sync.WaitGroup

	// call different endpoints concurrently and repeatedly
	for range 30 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			// random delay up to 500 ms
			n := rand.IntN(500)
			time.Sleep(time.Duration(n) * time.Millisecond)
			_, err := awsTestEnv.sessionClient.AboutMe()
			require.Nil(t, err)
		}()
		go func() {
			defer wg.Done()
			// random delay up to 500 ms
			n := rand.IntN(500)
			time.Sleep(time.Duration(n) * time.Millisecond)
			endpoint, err := awsTestEnv.sessionClient.BuildEndpointUrl("/v0/org/{org_id}", nil, nil)
			require.Nil(t, err)
			_, err = awsTestEnv.sessionClient.SendRequest("GET", endpoint, nil, nil)
			require.Nil(t, err)
		}()
		go func() {
			defer wg.Done()
			// random delay up to 500 ms
			n := rand.IntN(500)
			time.Sleep(time.Duration(n) * time.Millisecond)
			endpoint, err := awsTestEnv.sessionClient.BuildEndpointUrl("/v0/org/{org_id}/session", nil, nil)
			require.Nil(t, err)
			_, err = awsTestEnv.sessionClient.SendRequest("GET", endpoint, nil, nil)
			require.Nil(t, err)
		}()
	}

	wg.Wait()
}
