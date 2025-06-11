package client

import (
	"fmt"
	"runtime"

	"github.com/cubist-labs/cubesigner-go-sdk/models"
	"github.com/cubist-labs/cubesigner-go-sdk/session"
	"github.com/cubist-labs/cubesigner-go-sdk/utils/ref"
)

// noSessionManager implements [session.SessionManager] and is an internal
// utility type used to instantiate session-less clients. Such clients
// are used to invoke API endpoints that do not require CubeSigner session.
type noSessionManager struct {
	RootUrl string
	OrgID   string
}

// noSessionManager.Metadata implements [session.SessionManager.Metadata]
func (psm *noSessionManager) Metadata() session.SessionMetadata {
	return session.SessionMetadata{
		OrgID:   psm.OrgID,
		RootUrl: psm.RootUrl,
	}
}

// noSessionManager.Token implements [session.SessionManager.Token]
// and always returns an empty string.
func (psm *noSessionManager) Token() (string, error) {
	return "", nil
}

// GenericHttpResponse is a simplified
// structure for http responses.
type GenericHttpResponse struct {
	Status     string
	StatusCode uint64
	Body       string
}

// CubeSignerResponse is returned by any endpoint
// that may need an MFA approval. MfaRequired
// is set only when MFA is required, and ResponseData
// is nil. Vice versa is true when mfa is not required,
// that is, MfaRequired is nil and ResponseData is set.
type CubeSignerResponse[T any] struct {
	MfaRequired  *AcceptedValueMfaRequired
	ResponseData *T
}

// RequiresMfa returns true if MFA is required for a CubeSignerResponse.
func (cubeSignerResp CubeSignerResponse[_]) RequiresMfa() bool {
	return cubeSignerResp.MfaRequired != nil
}

// newCubeSignerResponseFrom is a helper function to parse a generic CubeSignerResponse to type T and return a CubeSignerResponse
// of that type T.
func newCubeSignerResponseFrom[T any](resp *CubeSignerResponse[GenericHttpResponse]) (*CubeSignerResponse[T], error) {
	if resp.RequiresMfa() {
		return &CubeSignerResponse[T]{MfaRequired: resp.MfaRequired}, nil
	}
	typedData, err := ParseGenericResponseInto[T](resp.ResponseData)
	if err != nil {
		return nil, err
	}
	return &CubeSignerResponse[T]{ResponseData: typedData}, nil
}

// Lifetime parameters for CubeSigner session creation. Denoted in seconds.
type Lifetimes struct {
	AuthLifetime    *int64 // default: 5 minutes
	GraceLifetime   *int64 // default: 30 seconds
	RefreshLifetime *int64 // default: 1 day
	SessionLifetime *int64 // default: 1 year
	ExtendLifetimes *bool  // default: false (MFA required on true)
}

// NewOsInfo returns OS information detected by the SDK. This is
// embedded is session create requests.
func newOsInfo() *models.OsInfo {
	return &models.OsInfo{
		Architecture: ref.Of(runtime.GOARCH),
		Name:         ref.Of(runtime.GOOS),
	}
}

// NewClientInfo returns the client (SDK) information. This
// is embedded in session create requests.
func newClientInfo() *models.ClientProfile {
	return &models.ClientProfile{
		Agent:   ref.Of("Go SDK"),
		Engine:  ref.Of("GoLang"),
		Version: ref.Of("0.0.1"),
	}
}

// NewCreateSessionRequest is a helper function used by the client to prepare the request body for CreateSession API endpoint.
// Purpose and scopes are required.
func NewCreateSessionRequest(purpose string, scopes []models.Scope, lifetimes *Lifetimes) *models.CreateSessionRequest {
	reqBody := models.CreateSessionRequest{}
	// Lifetimes
	if lifetimes != nil {
		reqBody.AuthLifetime = lifetimes.AuthLifetime
		reqBody.GraceLifetime = lifetimes.GraceLifetime
		reqBody.RefreshLifetime = lifetimes.RefreshLifetime
		reqBody.SessionLifetime = lifetimes.SessionLifetime
		reqBody.ExtendLifetimes = lifetimes.ExtendLifetimes
	}
	// OsInfo
	reqBody.OsInfo = newOsInfo()
	// Client
	reqBody.Client = newClientInfo()
	// Purpose and Scope (required)
	reqBody.Purpose = purpose
	reqBody.Scopes = scopes

	return &reqBody
}

// CubeSignerError wraps the http status code with
// models.ErrorResponse.
type CubeSignerError struct {
	StatusCode int
	Body       models.ErrorResponse
}

func (errResp CubeSignerError) Error() string {
	requestId := ""
	if errResp.Body.RequestId != nil {
		requestId = *errResp.Body.RequestId
	}
	return fmt.Sprintf("%s (Status: %d) [Request ID: %s] [Error Code: %s]", errResp.Body.Message, errResp.StatusCode, requestId, errResp.Body.ErrorCode)
}

// AcceptedValueMfaRequired is an optional part of
// CubeSignerResponse and represents the information
// for the required MFA approval.
type AcceptedValueMfaRequired struct {
	// always set to first MFA id from Ids
	Id string `json:"id"`
	// non-empty MFA request IDs
	Ids []string `json:"ids"`
	// organization id
	OrgId string `json:"org_id"`
}
