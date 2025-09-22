package session

import (
	"encoding/json"
	"os"

	"github.com/cubist-labs/cubesigner-go-sdk/utils"
)

// JsonSessionManager encapsulates session information that is maintained
// for a session stored in a json file. JsonSessionManager implements
// the [SessionManager] interface.
//
// JsonSessionManager is safe for concurrency.
type JsonSessionManager struct {
	// path to session file
	FilePath string
	// concurrency safe session data
	safeSessionData *safeSessionData
}

// NewJsonSessionManager returns a pointer to a JsonSessionManager that
// is populated with the provided session file. If no session file is provided
// the default cs session file path is used to load the session.
func NewJsonSessionManager(sessionFilePath *string) (*JsonSessionManager, error) {
	var path string
	var err error
	if sessionFilePath == nil {
		path, err = utils.GetDefaultSessionFilePath()
		if err != nil {
			return nil, err
		}
	} else {
		path = *sessionFilePath
	}
	sessionData, err := GetSessionFromFile(path)
	if err != nil {
		return nil, err
	}

	return &JsonSessionManager{
		FilePath:        path,
		safeSessionData: safeSessionDataFrom(sessionData),
	}, nil
}

// JsonSessionManager.Metadata implements [session.SessionManager.Metadata]
// and returns the session metadata.
func (manager *JsonSessionManager) Metadata() SessionMetadata {
	return manager.safeSessionData.metadata()
}

// JsonSessionManager.Token implements [session.SessionManager.Token]
// and returns a non-expired token, calling the manager refresh method if
// it is expired. The validity criteria is based on token lifetimes.
func (manager *JsonSessionManager) Token() (string, error) {
	if err := manager.refreshIfNeeded(); err != nil {
		return "", err
	}
	return manager.safeSessionData.token(), nil
}

// JsonSessionManager.refreshIfNeeded refreshes the session if the session
// auth token has expired, the refresh token is valid, and the session
// lifetime is valid. The refresh endpoint is only invoked internally if
// the aforementioned conditions are met. JsonSessionManager.refreshIfNeeded
// returns an error if the session can no longer be refreshed.
//
// The json file is also updated upon refreshing the session.
func (manager *JsonSessionManager) refreshIfNeeded() error {
	// update the session file if a refresh is performed
	// -- -- -- -- -- -- --- -- -- -- -- -- -- -- onRefresh() callback
	return manager.safeSessionData.refreshIfNeeded(func() error {
		// onRefresh is protected under safeSessionData.lock so it safe to access safe safeSessionData.data
		out, err := json.MarshalIndent(manager.safeSessionData.data, "", "  ")
		if err != nil {
			return err
		}

		// Overwrite
		file, err := os.OpenFile(manager.FilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = file.Write(out)
		if err != nil {
			return err
		}

		return nil
	})
}
