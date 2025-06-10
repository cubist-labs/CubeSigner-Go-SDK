// Package client provides the CubeSigner API Client to interface with
// various endpoints.
package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cubist-labs/cubesigner-go-sdk/models"
	"github.com/cubist-labs/cubesigner-go-sdk/session"
	"github.com/cubist-labs/cubesigner-go-sdk/utils"
)

// ApiClient wraps Http client with relevant information
// needed to execute api calls.
type ApiClient struct {
	RootUrl    string
	HttpClient *http.Client
	Manager    SessionManager
}

// payload extends a typical http payload with
// CubeSigner relevant mfaReceipts.
type payload struct {
	method      string
	path        string
	pathParams  map[string]string
	queryParams map[string]string
	headers     map[string]string
	body        any
	mfaReceipts []*MfaReceipt
}

// NewApiClient returns a pointer to a new ApiClient.
func NewApiClient(manager SessionManager) (*ApiClient, error) {
	sessionMetaData := manager.Metadata()

	return &ApiClient{
		RootUrl:    sessionMetaData.RootUrl,
		HttpClient: utils.GetHttpClient(),
		Manager:    manager,
	}, nil
}

// send is a helper function for client that builds a url endpoint and sends the provided payload
// to that endpoint. Returns a CubeSignerResponse which may contain MFA required response.
func (client *ApiClient) send(payload *payload) (*CubeSignerResponse[GenericHttpResponse], error) {
	apiEndpoint, err := client.BuildEndpointUrl(payload.path, payload.pathParams, payload.queryParams)
	if err != nil {
		return nil, err
	}
	return client.SendRequest(payload.method, apiEndpoint, payload.body, payload.headers, payload.mfaReceipts...)
}

// sendAndAssertNoMfa is a helper function for client that builds a url endpoint and sends the provided payload
// to that endpoint. Returns a GenericHttpResponse and requires that the response will not need MFA
// handling.
func (client *ApiClient) sendAndAssertNoMfa(payload *payload) (*GenericHttpResponse, error) {
	apiEndpoint, err := client.BuildEndpointUrl(payload.path, payload.pathParams, payload.queryParams)
	if err != nil {
		return nil, err
	}
	resp, err := client.SendRequest(payload.method, apiEndpoint, payload.body, payload.headers)
	if err != nil {
		return nil, err
	}
	if resp.RequiresMfa() {
		return nil, errors.New("client got unexpected MFA response")
	}
	return resp.ResponseData, err
}

// OAuth2Refresh is a token refresh endpoint, compliant with OAuth. The body content type
// can be either `application/json` or `application/x-www-form-urlencoded`. This is set
// by the `Content-Type` header.
// Required scopes: None.
func (client *ApiClient) OAuth2Refresh(tokenRequest any, contentType *string) (*GenericHttpResponse, error) {
	contentHeader := make(map[string]string)
	if contentType != nil {
		contentHeader["Content-Type"] = *contentType
	}
	return client.sendAndAssertNoMfa(&payload{
		method:  "POST",
		path:    "/v0/oauth/token",
		body:    tokenRequest,
		headers: contentHeader,
	})
}

// MfaVoteEmailInit initiates an Email OTP MFA Approval/Rejection. Initiates the approval/rejection
// process of an MFA Request using Email OTP.
//
// Required Scopes: manage:mfa:vote:email
func (client *ApiClient) MfaVoteEmailInit(mfaId string, mfaVote models.MfaVote) (*EmailChallenge, error) {
	queryParams := make(map[string]string)
	voteStr := fmt.Sprintf("%v", mfaVote)
	queryParams["mfa_vote"] = voteStr
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/mfa/{mfa_id}/email",
		pathParams:  map[string]string{"mfa_id": mfaId},
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	var respBody struct {
		PartialToken string `json:"partial_token"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &respBody); err != nil {
		return nil, err
	}
	return &EmailChallenge{MfaId: mfaId, apiClient: client, PartialToken: respBody.PartialToken}, nil
}

// CreateSession creates and returns a new user session in response body, silently truncating requested session
// and auth lifetimes to be at most requestor's session and auth lifetime, respectively. To extend the requested
// lifetimes past the requestor's, set the `extend_lifetimes` flag in lifetimes parameter (in which case MFA will
// be required).
//
// CreateSession adds additional environment information to the response before returning so that it can be used
// with a session manager.
//
// Required scopes: "manage:session:create".
func (client *ApiClient) CreateSession(purpose string, scopes []models.Scope, lifetimes *Lifetimes, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[session.SessionData], error) {
	requestBody := NewCreateSessionRequest(purpose, scopes, lifetimes)
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/session",
		body:        requestBody,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}

	if resp.RequiresMfa() {
		return &CubeSignerResponse[session.SessionData]{MfaRequired: resp.MfaRequired}, nil
	}

	// Parse the session data from body
	sessionData, err := ParseGenericResponseInto[session.SessionData](resp.ResponseData)
	if err != nil {
		return nil, err
	}
	// Augment missing Root URL and Org ID
	sessionData.AugmentEnvAndOrgID(client.RootUrl, client.Manager.Metadata().OrgID)

	return &CubeSignerResponse[session.SessionData]{
		ResponseData: sessionData,
	}, nil
}

// CreateRoleSession creates a new access token for a given role (to be used as "API Key" for all signing actions).
// Only users in the role or owners can create a token for it.
//
// CreateRoleSession adds additional environment information to the response before returning so that it can be used
// with a session manager.
func (client *ApiClient) CreateRoleSession(roleId string, createTokenRequest models.CreateTokenRequest) (*session.SessionData, error) {
	resp, err := client.CreateRoleToken(roleId, createTokenRequest)
	if err != nil {
		return nil, err
	}
	// Parse the session data from body
	sessionData := session.SessionData{
		RefreshToken: resp.RefreshToken,
		SessionInfo:  &resp.SessionInfo,
		Token:        resp.Token,
	}
	if resp.Expiration != nil {
		sessionData.Expiration = uint64(*resp.Expiration)
	}
	sessionData.AugmentEnvAndOrgID(client.RootUrl, client.Manager.Metadata().OrgID)

	return &sessionData, nil
}

// OidcAuth exchanges an OIDC ID token (passed via the `Authorization` header) for a signer session.
//
// MFA is required when:
// - an MFA policy is explicitly attached to the user logging in
// (e.g., an org owner can do that at user creation time to require certain kind of MFA)
// - the user has at least 1 MFA factor configured
func OidcAuth(env session.EnvInterface, orgId string, oidcToken string, oidcLoginRequest models.OidcLoginRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[session.SessionData], error) {
	client, err := NewApiClient(&noSessionManager{OrgID: orgId, RootUrl: env.Spec.SignerApiRoot})
	if err != nil {
		return nil, err
	}
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/oidc",
		body:        oidcLoginRequest,
		mfaReceipts: mfaReceipts,
		headers:     map[string]string{"Authorization": oidcToken},
	})
	if err != nil {
		return nil, err
	}

	if resp.RequiresMfa() {
		return &CubeSignerResponse[session.SessionData]{MfaRequired: resp.MfaRequired}, nil
	}

	// Parse the session data from body
	sessionData, err := ParseGenericResponseInto[session.SessionData](resp.ResponseData)
	if err != nil {
		return nil, err
	}

	// Augment missing Root URL and Org ID
	sessionData.AugmentEnvAndOrgID(client.RootUrl, client.Manager.Metadata().OrgID)

	return &CubeSignerResponse[session.SessionData]{
		ResponseData: sessionData,
	}, nil
}

// SendRequest sends the provided Http request after attaching session credential headers
// and Marshalling the request body (if any). Any MFA approval receipts are also attached.
// On a 5XX response, SendRequest will retry the request up to 3 times with a 5 second interval.
// Non-2XX response is treated as an error. SendRequest returns a CubeSignerResponse which will
// either have MfaRequired field set (when MFA is required) or ResponseData field set (when MFA
// is not required).
func (client *ApiClient) SendRequest(method string, route string, body any, headers map[string]string, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[GenericHttpResponse], error) {
	// marshal
	var mBody []byte = nil
	var err error
	if body != nil {
		mBody, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}

	request, err := http.NewRequest(method, route, bytes.NewBuffer(mBody))
	if err != nil {
		return nil, err
	}
	mfaHeaders, err := getMfaConfirmationHeaders(client.Manager.Metadata().OrgID, mfaReceipts)
	if err != nil {
		return nil, err
	}
	for key, val := range mfaHeaders {
		request.Header.Add(key, val)
	}

	_, exists := headers["Authorization"]
	if !exists {
		authToken, err := client.Manager.Token()
		if err != nil {
			return nil, err
		}
		request.Header.Add("Authorization", authToken)
	}

	for key, val := range headers {
		request.Header.Add(key, val)
	}

	resp, err := utils.RetryOn5XX(client.HttpClient, request)
	if err != nil {
		return nil, err
	}
	// check for 202: Mfa required
	mfaResponse, err := parseAndGetMfaResponse[GenericHttpResponse](resp)
	if mfaResponse != nil || err != nil {
		return mfaResponse, err
	}
	// otherwise return generic http response
	parsedResp, err := parseHttpResponse(resp)
	if err != nil {
		return nil, err
	}
	return &CubeSignerResponse[GenericHttpResponse]{ResponseData: parsedResp}, nil
}

// BuildEndpointUrl is a helper to construct the endpoint string. Given an generic endpoint path from CubeSigner Api reference
// e.g. `/v0/org/{org_id}/mfa/{mfa_id}`, BuildEndpointUrl will automatically:
//   - resolve {org_id}
//   - prepend the root URL
//
// Other placeholders and query parameters need to be provided as arguments. BuildEndPointUrl accepts map[string]string to
// map key-value pairs for path and query arguments. e.g. in the previous example:
//   - `pathParams = {"mfa_id": "<mfa_id>"}`
//   - `queryParams = {"mfa_vote": "approve"}`
//
// Keys must omit "{}" characters.
func (client *ApiClient) BuildEndpointUrl(endpoint string, pathParams map[string]string, queryParams map[string]string) (string, error) {
	if endpoint == "" {
		return "", errors.New("endpoint cannot be nil")
	}
	if pathParams == nil {
		pathParams = make(map[string]string)
	}
	pathParams["org_id"] = client.Manager.Metadata().OrgID
	for key, val := range pathParams {
		endpoint = strings.ReplaceAll(endpoint, "{"+key+"}", url.QueryEscape(val))
	}
	endpointURL, err := url.Parse(client.RootUrl)
	if err != nil {
		return "", err
	}
	endpointURL = endpointURL.JoinPath(endpoint)
	endpointURL = addQueryParams(endpointURL, queryParams)

	return endpointURL.String(), nil
}

// ParseHTTPResponse returns a simplified GenericHttpResponse object
// that encapsulates the status and the response body as string.
func parseHttpResponse(response *http.Response) (*GenericHttpResponse, error) {
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != 200 && response.StatusCode != 202 {
		var errRespBody models.ErrorResponse
		if err := json.Unmarshal(body, &errRespBody); err != nil {
			return nil, err
		}
		errResp := CubeSignerError{
			StatusCode: response.StatusCode,
			Body:       errRespBody,
		}
		return nil, errResp
	}

	return &GenericHttpResponse{
		Status:     response.Status,
		StatusCode: uint64(response.StatusCode),
		Body:       string(body),
	}, nil
}

// getMfaConfirmation returns MFA confirmation http headers from approved MFA receipts. These
// headers need to be included when resubmitting the original request that required MFA.
func getMfaConfirmationHeaders(orgId string, mfaRecs []*MfaReceipt) (map[string]string, error) {
	if mfaRecs == nil {
		return nil, nil
	}

	var nonNilReceipts []*MfaReceipt
	for _, req := range mfaRecs {
		// skip nil requests
		if req == nil {
			continue
		}
		nonNilReceipts = append(nonNilReceipts, req)
	}

	// if nil MfaRec are passed
	if len(nonNilReceipts) == 0 {
		return nil, nil
	}

	bytes, err := json.Marshal(nonNilReceipts)
	if err != nil {
		return nil, err
	}
	encodedReceipts := base64.RawURLEncoding.EncodeToString(bytes)

	headers := make(map[string]string)
	headers["x-cubist-mfa-org-id"] = orgId
	headers["x-cubist-mfa-receipts"] = encodedReceipts

	return headers, nil
}

// addQueryParam adds the provided query parameters to the provided URL
func addQueryParams(endpointUrl *url.URL, params map[string]string) *url.URL {
	endpointQuery := endpointUrl.Query()
	for k, v := range params {
		endpointQuery.Set(k, v)
	}
	endpointUrl.RawQuery = endpointQuery.Encode()

	return endpointUrl
}

// parseAndGetMfaResponse parses a 202 http response to fetch MFA information. If the response
// does not have a 202 status, it returns nil.
func parseAndGetMfaResponse[T any](response *http.Response) (*CubeSignerResponse[T], error) {
	if response.StatusCode != 202 {
		return nil, nil
	}
	parsedResp, err := parseHttpResponse(response)
	if err != nil {
		return nil, err
	}
	errRespBody, err := ParseGenericResponseInto[models.ErrorResponse](parsedResp)
	if err != nil {
		return nil, err
	}
	acceptedVal := errRespBody.Accepted
	return &CubeSignerResponse[T]{MfaRequired: &AcceptedValueMfaRequired{
		Id:    acceptedVal.MfaRequired.Id,
		Ids:   acceptedVal.MfaRequired.Ids,
		OrgId: acceptedVal.MfaRequired.OrgId,
	}}, nil
}

// ParseGenericResponseInto tries to parses a GenericHttpResponse into any type that
// implements json.Unmarshal. Under the hood, this function wraps json.Unmarshal with
// generics.
func ParseGenericResponseInto[T any](response *GenericHttpResponse) (*T, error) {
	var t T
	if err := json.Unmarshal([]byte(response.Body), &t); err != nil {
		return nil, err
	}
	return &t, nil
}
