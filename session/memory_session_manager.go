package session

// MemorySessionManager is a wrapper around session data that is
// maintained in memory. MemorySessionManager implements the
// [client/SessionManager] interface.
//
// MemorySessionManager is safe for concurrency.
type MemorySessionManager struct {
	// concurrency safe session data
	safeSessionData *safeSessionData
}

// NewMemorySessionManager returns an in-memory session manager.
func NewMemorySessionManager(sessionData *SessionData) *MemorySessionManager {
	return &MemorySessionManager{
		safeSessionData: safeSessionDataFrom(sessionData),
	}
}

// MemorySessionManager.Metadata implements [SessionManager.Metadata]
// and returns the session metadata.
func (manager *MemorySessionManager) Metadata() SessionMetadata {
	return manager.safeSessionData.metadata()
}

// MemorySessionManager.Token implements [SessionManager.Token]
// and returns a non-expired token, calling the manager refresh method if
// it is expired. The validity criteria is based on token lifetimes.
func (manager *MemorySessionManager) Token() (string, error) {
	if err := manager.refreshIfNeeded(); err != nil {
		return "", err
	}
	return manager.safeSessionData.token(), nil
}

// MemorySessionManager.refreshIfNeeded refreshes the session if the session auth token
// has expired, the refresh token is valid, and the session lifetime is valid.
// The refresh endpoint is only invoked internally if the aforementioned
// conditions are met. MemorySessionManager.refreshIfNeeded returns an error if the
// session can no longer be refreshed.
func (manager *MemorySessionManager) refreshIfNeeded() error {
	// No manager-specific action on a refresh.
	return manager.safeSessionData.refreshIfNeeded(nil)
}
