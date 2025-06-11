package session

// SessionManager's job is to handle session persistence and refreshes.
// This interface is used by the client when invoking API endpoints.
type SessionManager interface {
	// Retrieve non-sensitive session information.
	Metadata() SessionMetadata
	// Retrieve a valid authentication token. If the current token is stale,
	// a refresh is attempted to return a valid token.
	Token() (string, error)
}
