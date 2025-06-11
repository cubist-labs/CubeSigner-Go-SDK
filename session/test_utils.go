package session

// NewTestAwsSessionManager is a testing utility and returns an AwsSessionManager
// with mock aws secrets client for testing purposes.
func NewTestAwsSessionManager(secretId string, mockAwsClient SecretsManagerClientAPI, cacheLifetime *uint64) (*AwsSessionManager, error) {
	manager := AwsSessionManager{
		secretId:         secretId,
		safeSessionCache: &safeSessionCache{},
		secretsManager:   mockAwsClient,
		opts: &AwsSecretSessionManagerOpts{
			AwsCfg:                 nil,
			CheckScheduledRotation: true,
			MaxCacheLifetime:       cacheLifetime, // in seconds
		},
	}
	// pull session data
	if err := manager.updateCacheIfNeeded(); err != nil {
		return nil, err
	}

	return &manager, nil
}

// NewTestAwsSecretManager is a testing utility and returns a AwsSecretManager with mock
// aws secrets client for testing purposes.
func NewTestAwsSecretManager(secretArn string, mockAwsClient SecretsManagerClientAPI) (*AwsSecretManager, error) {
	return &AwsSecretManager{
		secretArn:      secretArn,
		secretsManager: mockAwsClient,
	}, nil
}
