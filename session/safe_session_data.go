package session

import (
	"sync"
)

// safeSessionData protects its SessionData state with a read-write
// mutex making it safe for concurrency. All accesses to safeSessionData
// must be made through its methods to prevent race conditions. Every
// safeSessionData method obtains an appropriate read or write lock and
// no safeSessionData method may ever call another safeSessionData method
// to avoid deadlocks. safeSessionData methods call underlying sessionData
// methods which do not use any locking.
type safeSessionData struct {
	// read-write mutex
	lock sync.RWMutex
	// session data. Must not be accessed directly.
	data *SessionData
}

// SafeSessionDataFrom creates safeSessionData from SessionData.
// SessionData must be converted to safeSessionData when being used
// in concurrent executions. SafeSessionDataFrom creates a copy
// from the argument pointer to avoid referencing afterwards.
func safeSessionDataFrom(sessionData *SessionData) *safeSessionData {
	// create a copy to avoid pointer referencing
	sessionDataCopy := *sessionData
	return &safeSessionData{data: &sessionDataCopy}
}

// safeSessionData.refreshIfNeeded checks if the session has expired, and attempts
// to refresh it if needed. If the session cannot be refreshed due to session
// lifetime or refresh token being expired, an error is returned.
// If the refresh is successful, the onRefresh callback is invoked. onRefresh
// is protected under safeSessionData.lock so it is safe to access safeSessionData.data
// in the function body. onRefresh must not acquire any safeSessionData locks.
func (safeSessionData *safeSessionData) refreshIfNeeded(onRefresh func() error) error {
	isExpired, err := func() (bool, error) {
		safeSessionData.lock.RLock()
		defer safeSessionData.lock.RUnlock()

		return safeSessionData.data.needsRefreshing()
	}()
	if err != nil {
		return err
	}

	if !isExpired {
		return nil
	}

	// obtain write lock only if session is expired
	safeSessionData.lock.Lock()
	defer safeSessionData.lock.Unlock()

	// update session data if needed
	isRefreshed, err := safeSessionData.data.refreshIfNeeded()
	if err != nil {
		return err
	}

	// perform onRefresh action if any upon refresh
	if onRefresh != nil && isRefreshed {
		return onRefresh()
	}

	return nil
}

// safeSessionData.metadata extracts SessionMetadata from SessionData and
// returns it.
func (safeSessionData *safeSessionData) metadata() SessionMetadata {
	safeSessionData.lock.RLock()
	defer safeSessionData.lock.RUnlock()

	return safeSessionData.data.metadata()
}

// safeSessionData.token returns the current session token.
func (safeSessionData *safeSessionData) token() string {
	safeSessionData.lock.RLock()
	defer safeSessionData.lock.RUnlock()

	return safeSessionData.data.Token
}
