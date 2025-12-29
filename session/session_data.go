// Package session provides managers and utilities for CubeSigner sessions. Managers
// allow automatic handling of token refreshes and access to session data. There are
// three managers in this package:
//
//   - AwsSessionManager: Manages sessions stored in aws secret manager
//   - JsonSessionManager: Manages sessions saved on disk in json format
//   - MemorySessionManager: Manages sessions in memory
//
// Each manager may only manage a single session at once.
package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/cubist-labs/cubesigner-go-sdk/models"
	"github.com/cubist-labs/cubesigner-go-sdk/utils"
)

// The number of seconds before expiration time, to attempt a refresh.
const DEFAULT_EXPIRATION_BUFFER_SECS uint64 = 30

// SessionData encapsulates all the data that represents a session.
// SessionData and its methods are not safe for concurrency.
type SessionData struct {
	// The organization ID
	OrgID string `json:"org_id"`
	// If a role is associated with this session, its ID
	RoleID string `json:"role_id,omitempty"`
	// Session expiration, beyond which it cannot be refreshed
	Expiration uint64 `json:"expiration"`
	// An arbitrary string to denote the session purpose
	Purpose string `json:"purpose,omitempty"`
	// The authentication token for this session.
	// Needed to authorize API calls.
	Token string `json:"token"`
	// Refresh token for Oauth
	RefreshToken string `json:"refresh_token"`
	// CubeSigner environment information
	Env *EnvInterface `json:"env,omitempty"`
	// Extended client session information and tokens
	SessionInfo *models.ClientSessionInfo `json:"session_info"`
}

// CubeSigner environment information
type EnvInterface struct {
	Spec *Spec `json:"Dev-CubeSignerStack"`
}

// Spec contains the root URL for API endpoints
type Spec struct {
	// The root URL for API endpoints
	SignerApiRoot string `json:"SignerApiRoot"`
}

// SessionMetadata contains non-sensitive session information.
type SessionMetadata struct {
	// The root url for api endpoints
	RootUrl string
	// The organization ID
	OrgID string
	// The session ID
	SessionID string
}

// GetSessionData retrieves session information from a json file and parses it.
func GetSessionFromFile(sessionFilePath string) (*SessionData, error) {
	file, err := os.Open(sessionFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	byteValue, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	var sessionData SessionData
	if err = json.Unmarshal(byteValue, &sessionData); err != nil {
		return nil, err
	}

	return &sessionData, nil
}

// SessionData.metadata extracts SessionMetadata from SessionData and
// returns it.
func (sessionData *SessionData) metadata() SessionMetadata {
	if sessionData == nil {
		return SessionMetadata{}
	}
	return SessionMetadata{
		RootUrl:   sessionData.Env.Spec.SignerApiRoot,
		OrgID:     sessionData.OrgID,
		SessionID: sessionData.SessionInfo.SessionId,
	}
}

// SessionData.updateSessionData updates a SessionData object with the new tokens,
// session information, and expiry in a refresh session response.
// No value is returned as the update happens by reference.
func (sessionData *SessionData) updateSessionData(update *refreshSession200Response) {
	sessionData.Expiration = update.Expiration
	sessionData.RefreshToken = update.RefreshToken
	sessionData.SessionInfo = update.SessionInfo
	sessionData.Token = update.Token
}

// SessionData.needsRefreshing will check if the session token is stale and
// refreshable. If so, it will return true. Otherwise, if
// the session is still valid it returns false. An error is
// is returned if the session has passed its refresh lifetime.
func (sessionData *SessionData) needsRefreshing() (bool, error) {
	if !sessionData.isStale() {
		return false, nil
	}
	// It is stale, check if refresh is possible
	if !sessionData.isRefreshable() {
		return false, errors.New("session cannot be refreshed")
	}

	return true, nil
}

// isWithinBuffer is a helper function that returns whether or not the timestamp
// is before + DEFAULT_EXPIRATION_BUFFER_SECS
func isWithinBuffer(timeInSeconds uint64) bool {
	return timeInSeconds < uint64(time.Now().Unix())+DEFAULT_EXPIRATION_BUFFER_SECS
}

func (sessionData *SessionData) isStale() bool {
	return isWithinBuffer(uint64(sessionData.SessionInfo.AuthTokenExp))
}

func (sessionData *SessionData) isRefreshable() bool {
	return !isWithinBuffer(sessionData.Expiration) &&
		!isWithinBuffer(uint64(sessionData.SessionInfo.RefreshTokenExp))
}

// SessionData.refreshIfNeeded checks if the session has expired,
// refreshes it if needed, and returns true if a refresh took place.
// Returns an error if the session cannot be refreshed (refresh
// token or session lifetime has expired).
func (sessionData *SessionData) refreshIfNeeded() (bool, error) {
	isExpired, err := sessionData.needsRefreshing()
	if err != nil {
		return false, err
	}
	if isExpired {
		// avoiding code duplication.
		// the refresh is not forced here
		// as we check for expirations above.
		// forceRefresh simply invokes the
		// refreshSession endpoint.
		return true, sessionData.forceRefresh()
	}
	return false, nil
}

// SessionData.forceRefresh directly invokes the refreshSession
// endpoint without checking any expiration timestamps. A valid
// unexpired session will be refreshed by forceRefresh,
// invalidating the current tokens after the grace lifetime is over.
func (sessionData *SessionData) forceRefresh() error {
	resp, err := sessionData.refreshSession()
	if err != nil {
		return err
	}
	sessionData.updateSessionData(resp)

	return nil
}

// refreshSession200Response is the response from
// the SessionData.refreshSession endpoint.
type refreshSession200Response struct {
	Expiration   uint64                    `json:"expiration"`
	RefreshToken string                    `json:"refresh_token"`
	SessionInfo  *models.ClientSessionInfo `json:"session_info"`
	Token        string                    `json:"token"`
}

// refreshSessionRequestBody is the request body sent
// by the SessionData.refreshSession endpoint.
type refreshSessionRequestBody struct {
	// The current epoch number for session
	EpochNum uint64 `json:"epoch_num"`
	// Epoch token for this session
	EpochToken string `json:"epoch_token"`
	// The current refresh token
	OtherToken string `json:"other_token"`
}

// SessionData.refreshSession invokes the `/v1/org/{org_id}/token/refresh` endpoint to fetch a
// valid token. The response is parsed and returned accordingly. If request status
// was not 200 then it is expected to fail as the refresh was unsuccessful.
// Required Scopes: None.
func (sessionData *SessionData) refreshSession() (*refreshSession200Response, error) {
	apiEndPoint := fmt.Sprintf("%s/v1/org/%s/token/refresh", sessionData.Env.Spec.SignerApiRoot, url.QueryEscape(sessionData.OrgID))
	reqObj := refreshSessionRequestBody{
		EpochNum:   uint64(sessionData.SessionInfo.Epoch),
		EpochToken: sessionData.SessionInfo.EpochToken,
		OtherToken: sessionData.SessionInfo.RefreshToken,
	}
	mReqBody, err := json.Marshal(reqObj)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest("PATCH", apiEndPoint, bytes.NewBuffer(mReqBody))
	if err != nil {
		return nil, err
	}
	request.Header.Add("Authorization", sessionData.Token)
	client := utils.GetHttpClient()

	resp, err := utils.RetryOn5XX(client, request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("refreshSession: non 200 response: %s: %s", resp.Status, string(body))
	}

	// Unmarshal the new session tokens, expiry, and information
	// in a 200 refresh session response.
	var parsedResponse refreshSession200Response
	if err := json.Unmarshal([]byte(body), &parsedResponse); err != nil {
		return nil, err
	}

	// Send heartbeat to confirm the refresh (while we're holding the lock in parallel environment).
	apiEndPoint = fmt.Sprintf("%s/v1/org/%s/cube3signer/heartbeat", sessionData.Env.Spec.SignerApiRoot, url.QueryEscape(sessionData.OrgID))
	request, err = http.NewRequest("POST", apiEndPoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Add("Authorization", parsedResponse.Token)
	_, err = utils.RetryOn5XX(client, request)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			body = []byte(err.Error())
		}
		return nil, fmt.Errorf("heartbeat: non 200 response: %s: %s", resp.Status, string(body))
	}

	return &parsedResponse, nil
}

// SessionData.AugmentEnvAndOrgID is a helper function used by the ApiClient to add missing
// RootURL and Org ID in CreateSession end-point response.
func (sessionData *SessionData) AugmentEnvAndOrgID(rootURL string, orgID string) {
	sessionData.Env = &EnvInterface{Spec: &Spec{SignerApiRoot: rootURL}}
	sessionData.OrgID = orgID
}

// SessionData.WriteToFile writes the session data to a file
func (sessionData *SessionData) WriteToFile(path string) error {
	out, err := json.MarshalIndent(sessionData, "", "  ")
	if err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(out)
	if err != nil {
		return err
	}

	return nil
}
