package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// safeSessionCache is the locally cached session information
// to reduce calls to aws secrets manager. safeSessionCache
// guards its state with a read-write lock. Access to cache must
// always be through safeSessionCache methods to prevent race
// conditions. Every safeSessionCache method obtains an appropriate
// read or write lock and no safeSessionCache method may ever call
// another safeSessionCache method to avoid deadlocks.
type safeSessionCache struct {
	// cache lock
	lock sync.RWMutex
	// Session information. Must not be accessed directly
	data *SessionData
	// Expiry epoch timestamp for the cache
	exp uint64
}

// safeSessionCache.isExpiredOrNil is safe for concurrency.
func (cache *safeSessionCache) isExpiredOrNil() bool {
	cache.lock.RLock()
	defer cache.lock.RUnlock()
	return cache.data == nil || cache.exp <= uint64(time.Now().Unix())+DEFAULT_EXPIRATION_BUFFER_SECS
}

// safeSessionCache.assign is a helper method for
// AwsSessionManager.updateCacheIfNeeded to assign new data and exp from
// secretsManager response. Assign does not create a copy of newData
// argument, and it is assumed that the newData pointer will not be
// used to reference the session data again. Secrets manager response in
// updateCacheIfNeeded is local and hence safe to use with assign.
//
// Safe for concurrency.
func (cache *safeSessionCache) assign(newData *SessionData, newExp uint64) {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	cache.data = newData
	cache.exp = newExp
}

// safeSessionCache.token reads and returns the cached token.
// Safe for concurrency.
func (cache *safeSessionCache) token() string {
	cache.lock.RLock()
	defer cache.lock.RUnlock()
	return cache.data.Token
}

// safeSessionCache.metadata returns SessionMetadata from the cached session.
// Safe for concurrency.
func (cache *safeSessionCache) metadata() SessionMetadata {
	cache.lock.RLock()
	defer cache.lock.RUnlock()
	return cache.data.metadata()
}

// AwsSecretSessionManagerOpts encapsulates aws configuration
// along with custom options for rotation and cache.
type AwsSecretSessionManagerOpts struct {
	// aws configuration
	AwsCfg *aws.Config
	// Limit the cache lifetime by the scheduled rotation of the secret.
	CheckScheduledRotation bool
	// Maximum amount of time that session data will be cached.
	MaxCacheLifetime *uint64
}

// SecretsManagerClientAPI is the interface implemented by aws secretsmanager.Client.
type SecretsManagerClientAPI interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	DescribeSecret(ctx context.Context, params *secretsmanager.DescribeSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
	UpdateSecret(ctx context.Context, params *secretsmanager.UpdateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretOutput, error)
}

// AwsSessionManager encapsulates session information that is maintained
// for a session stored in aws secrets manager. AwsSessionManager
// implements the [session.SessionManager] interface.
//
// AwsSessionManager is safe for concurrency.
type AwsSessionManager struct {
	// Secret id
	secretId string
	// Locally stored session information
	safeSessionCache *safeSessionCache
	// Secrets manager client
	secretsManager SecretsManagerClientAPI
	// Aws config and custom options
	opts *AwsSecretSessionManagerOpts
}

// NewAwsSessionManager creates and initializes a new AwsSessionManager. Upon creation, the manager
// pulls the secret from aws secrets manager. If no options are provided the routine attempts to load the
// default aws configuration on the system, checkScheduledRotation is set to true, and maxCacheLifetime is nil.
func NewAwsSessionManager(secretId string, opts *AwsSecretSessionManagerOpts) (*AwsSessionManager, error) {
	if opts == nil {
		// fetch default config
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, err
		}
		opts = &AwsSecretSessionManagerOpts{
			AwsCfg:                 &cfg,
			CheckScheduledRotation: true,
			MaxCacheLifetime:       nil,
		}
	}

	manager := AwsSessionManager{
		secretId:         secretId,
		safeSessionCache: &safeSessionCache{},
		secretsManager:   secretsmanager.NewFromConfig(*opts.AwsCfg),
		opts:             opts,
	}

	// pull session data
	if err := manager.updateCacheIfNeeded(); err != nil {
		return nil, err
	}

	return &manager, nil
}

// AwsSessionManager.Metadata implements [session.SessionManager.Metadata]
// and returns the session metadata.
func (manager *AwsSessionManager) Metadata() SessionMetadata {
	// metadata does not change for a session. Cache update
	// is not needed.
	return manager.safeSessionCache.metadata()
}

// AwsSessionManager.Token implements [session.SessionManager.Token]
// and returns the most recent token read from aws secrets manager.
func (manager *AwsSessionManager) Token() (string, error) {
	if err := manager.updateCacheIfNeeded(); err != nil {
		return "", err
	}
	return manager.safeSessionCache.token(), nil
}

// AwsSessionManager.updateCacheIfNeeded updates the manager cache if the cache
// is expired or nil.
func (manager *AwsSessionManager) updateCacheIfNeeded() error {
	// Check if the local cache is unexpired and non nil
	if !manager.safeSessionCache.isExpiredOrNil() {
		return nil
	}

	// otherwise attempt to pull data from aws secrets manager
	result, err := manager.secretsManager.GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(manager.secretId),
	})
	if err != nil {
		return err
	}
	str := *result.SecretString
	respSessionData, err := DecodeSessionBase64(str)
	if err != nil {
		return err
	}

	var exp uint64
	if manager.opts.MaxCacheLifetime != nil {
		exp = min(uint64(time.Now().Unix())+*manager.opts.MaxCacheLifetime, uint64(respSessionData.SessionInfo.AuthTokenExp))
	} else {
		exp = uint64(respSessionData.SessionInfo.AuthTokenExp)
	}

	// Limit cache lifetime by the next scheduled rotation if the user requested it
	if manager.opts.CheckScheduledRotation {
		out, err := manager.secretsManager.DescribeSecret(context.Background(), &secretsmanager.DescribeSecretInput{
			SecretId: &manager.secretId,
		})
		if err != nil {
			return err
		}
		if out.NextRotationDate != nil {
			exp = min(exp, uint64(out.NextRotationDate.Unix()))
		}
	}

	manager.safeSessionCache.assign(respSessionData, exp)

	return nil
}

// AwsSecretManager manages session data stored in AWS Secrets.
// This manager is typically used in rotation lambdas
// to periodically invoke AwsSecretManager.Refresh() to keep
// the session refreshed.
type AwsSecretManager struct {
	// ID of the secret
	secretArn string
	// Client for AWS secrets manager
	secretsManager SecretsManagerClientAPI
}

// NewAwsSecretManager initializes and returns a AwsSecret. If no aws configuration is
// provided, NewAwsSecretManager will attempt to load the default configuration.
func NewAwsSecretManager(secretArn string, awsCfg *aws.Config) (*AwsSecretManager, error) {
	if awsCfg == nil {
		// fetch default config
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, err
		}
		awsCfg = &cfg
	}

	return &AwsSecretManager{
		secretArn:      secretArn,
		secretsManager: secretsmanager.NewFromConfig(*awsCfg),
	}, nil
}

// AwsSecretManager.Refresh fetches the base64-encoded session secret stored in aws secrets,
// decodes the secret string, parses it as SessionData, refreshes the session,
// and writes back the updated session information as base64-encoded string in aws secrets.
// The session is refreshed unconditionally, ignoring any expiration timestamps. If the refresh
// token has expired or the session cannot be refreshed otherwise (.e.g, the session lifetime is over),
// the refresh will fail.
func (manager *AwsSecretManager) Refresh() error {
	// get secret session data
	result, err := manager.secretsManager.GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{
		SecretId: &manager.secretArn,
	})
	if err != nil {
		return err
	}

	// decode the session string into session data
	encodedSession := result.SecretString
	decodedSessionData, err := DecodeSessionBase64(*encodedSession)
	if err != nil {
		return err
	}
	// refresh unconditionally, ignoring expirations
	if err := decodedSessionData.forceRefresh(); err != nil {
		return err
	}

	// write back the updated session data
	if err := manager.update(decodedSessionData); err != nil {
		return err
	}

	return nil
}

// AwsSecretManager.update is a helper function to handle the UpdateSecret
// request to aws secrets. It is used to update the refreshed session in
// aws secrets.
func (manager *AwsSecretManager) update(sessionData *SessionData) error {
	encodedSession, err := EncodeSessionBase64(sessionData)
	if err != nil {
		return err
	}
	_, err = manager.secretsManager.UpdateSecret(context.Background(), &secretsmanager.UpdateSecretInput{
		SecretId:     &manager.secretArn,
		SecretString: &encodedSession,
	})
	if err != nil {
		return err
	}

	return nil
}

// EncodeSessionBase64 takes session data and encodes it into a base 64 string
func EncodeSessionBase64(sessionData *SessionData) (string, error) {
	bytes, err := json.Marshal(sessionData)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// DecodeSessionBase64 takes a base 64 string representing session data
// and decodes it into a SessionData object.
func DecodeSessionBase64(s string) (*SessionData, error) {
	bytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var sessionData SessionData
	err = json.Unmarshal(bytes, &sessionData)
	if err != nil {
		return nil, err
	}
	return &sessionData, nil
}
