package test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/cubist-labs/cubesigner-go-sdk/client"
	"github.com/cubist-labs/cubesigner-go-sdk/models"
	. "github.com/cubist-labs/cubesigner-go-sdk/session"
	"github.com/cubist-labs/cubesigner-go-sdk/spec/env"
	"github.com/cubist-labs/cubesigner-go-sdk/utils"
	"github.com/cubist-labs/cubesigner-go-sdk/utils/ref"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

type testingEnv struct {
	jsonSessionManager *JsonSessionManager
	jsonClient         *ApiClient
}

var testEnv testingEnv

func init() {
	var err error
	testEnv.jsonSessionManager, err = NewJsonSessionManager(nil)
	if err != nil {
		panic(fmt.Errorf("INIT: Failed to create a manager: %s\n", err))
	}
	testEnv.jsonClient, err = NewApiClient(testEnv.jsonSessionManager)
	if err != nil {
		panic(fmt.Errorf("INIT: Failed to create an ApiClient: %s\n", err))
	}
}

type signPolicy string

// AllowRawBlobSignPolicy allows the key the sign a Raw blob when added
// to its sign policy
const allowRawBlobSigningPolicy signPolicy = "AllowRawBlobSigning"

func writeSessionToFile(data *SessionData, path string) {
	if err := data.WriteToFile(path); err != nil {
		panic(fmt.Errorf("Failed to write session to file: %s\n", err))
	}
}

func createSigningBlobKey(mfaPolicy RequireMfaPolicy, editPolicy *models.EditPolicy) (string, error) {
	keyType := models.Ed25519SuiAddr
	signPolicy := []interface{}{&mfaPolicy, allowRawBlobSigningPolicy}
	createKeyReq := models.CreateKeyRequest{KeyType: keyType, Count: 1, Policy: &signPolicy, EditPolicy: editPolicy}
	keyInfo, err := testEnv.jsonClient.CreateKey(createKeyReq)
	if err != nil {
		return "", err
	}
	// read and check if the key type is correct
	if keyInfo.Keys[0].KeyType != models.Ed25519SuiAddr {
		return "", errors.New("KeyType mismatch")
	}
	return keyInfo.Keys[0].KeyId, nil
}

func getTotp() string {
	totpSecret := os.Getenv("TOTP_SECRET")
	totp, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		panic("failed to generate totp from secret")
	}
	return totp
}

func deleteTestKey(t *testing.T, client *ApiClient, keyId string) {
	// delete key
	deleteResp, err := client.DeleteKey(keyId)
	require.NoError(t, err)
	require.False(t, deleteResp.RequiresMfa())
}

func deleteTestUser(t *testing.T, client *ApiClient, userId string) {
	_, err := client.DeleteUser(userId)
	require.NoError(t, err)
}

func signBlob(t *testing.T, client *ApiClient, message string, keyId string, receipts ...*MfaReceipt) *CubeSignerResponse[models.SignResponse] {
	signRequestBody := models.BlobSignRequest{
		MessageBase64: base64.StdEncoding.EncodeToString([]byte(message)),
	}
	// try signing
	signResp, err := client.BlobSign(keyId, signRequestBody, receipts...)
	require.NoError(t, err)

	return signResp
}

func TestSessionGet(t *testing.T) {
	params := models.ListSessionsParams{
		PageSize: ref.Of(int32(1000)),
	}
	response, err := testEnv.jsonClient.ListSessions(&params)
	require.NoError(t, err)

	for len(response.Sessions) == 0 && response.LastEvaluatedKey != nil {
		params.PageStart = response.LastEvaluatedKey
		response, err = testEnv.jsonClient.ListSessions(&params)
		require.NoError(t, err)
	}

	// check if scope has manage all for first element
	require.NotNil(t, response.Sessions[0].Scopes)
	found := false

	for _, session := range response.Sessions {
		for _, scope := range *session.Scopes {
			if scope == "manage:*" {
				found = true
				break
			}
		}
		if found {
			break
		}
	}

	require.True(t, found)
}

func TestCreateSession(t *testing.T) {
	// get user id to check later
	resp1, err := testEnv.jsonClient.AboutMe()
	require.NoError(t, err)
	// Create a session
	respSession, err := testEnv.jsonClient.CreateSession("Test session", []models.Scope{"manage:*"}, nil)
	require.NoError(t, err)

	// make a new manager
	memManager := NewMemorySessionManager(respSession.ResponseData)
	client, err := NewApiClient(memManager)
	require.NoError(t, err)

	// test this client
	resp2, err := client.AboutMe()
	require.NoError(t, err)
	require.Equal(t, resp1.UserId, resp2.UserId)
}

func TestCreateSessionMfa(t *testing.T) {
	// Create a session that requires MFA
	lifetimes := &Lifetimes{
		ExtendLifetimes: ref.Of(true),
	}
	sessionResp, err := testEnv.jsonClient.CreateSession("Test session", []models.Scope{"manage:*"}, lifetimes)
	require.NoError(t, err)
	require.True(t, sessionResp.RequiresMfa())

	// try approve with cubesigner session: should fail
	_, err = testEnv.jsonClient.MfaVoteCs(sessionResp.MfaRequired.Id, &models.MfaVoteCsParams{MfaVote: ref.Of(models.Approve)})
	require.NotNil(t, err)
	require.True(t, strings.Contains(err.Error(), "MfaTypeNotAllowed"))

	// approve mfa
	totpResp, err := testEnv.jsonClient.MfaVoteTotp(sessionResp.MfaRequired.Id, &models.MfaVoteTotpParams{MfaVote: ref.Of(models.Approve)}, models.TotpApproveRequest{Code: getTotp()})
	require.NoError(t, err)
	require.NotNil(t, GetReceipt(totpResp))
	// resubmit
	sessionResp, err = testEnv.jsonClient.CreateSession("Test session", []models.Scope{"manage:*"}, lifetimes, GetReceipt(totpResp))
	require.NoError(t, err)
	// ensure no mfa in response
	require.False(t, sessionResp.RequiresMfa())

	// use this session
	memManager := NewMemorySessionManager(sessionResp.ResponseData)
	newClient, err := NewApiClient(memManager)
	require.NoError(t, err)

	_, err = newClient.AboutMe()
	require.NoError(t, err)
}

// Test that error is returned as expected
// instead of MfaRequired response.
func TestSignFailure(t *testing.T) {
	// get user id
	userResp, err := testEnv.jsonClient.AboutMe()
	require.NoError(t, err)
	numAuthFactors := int32(1)
	// test single auth factor with CubeSigner
	mfaPolicy := RequireMfaPolicy{
		RequireMfa: &models.MfaPolicy{
			Count:            ref.Of(int32(1)),
			NumAuthFactors:   &numAuthFactors,
			AllowedApprovers: ref.Of([]string{userResp.UserId}),
			AllowedMfaTypes:  ref.Of([]models.MfaType{CubeSignerMfaType()}),
		},
	}
	// send a bad request to SignBlob
	keyType := models.Ed25519SuiAddr
	signPolicy := []interface{}{&mfaPolicy}
	// no allow raw blob signing
	createKeyReq := models.CreateKeyRequest{KeyType: keyType, Count: 1, Policy: &signPolicy}
	keyInfo, err := testEnv.jsonClient.CreateKey(createKeyReq)
	require.NoError(t, err)

	keyId := keyInfo.Keys[0].KeyId
	signBlobRequest := models.BlobSignRequest{MessageBase64: base64.StdEncoding.EncodeToString([]byte("testMessage"))}
	// try signing
	_, err = testEnv.jsonClient.BlobSign(keyId, signBlobRequest)
	// should fail
	require.NotNil(t, err)
	require.True(t, strings.Contains(err.Error(), "RawSigningNotAllowed"))
}

func TestMfaSignCs(t *testing.T) {
	// get user id
	userResp, err := testEnv.jsonClient.AboutMe()
	require.NoError(t, err)

	numAuthFactors := int32(1)
	// test single auth factor with CubeSigner
	mfaPolicy := RequireMfaPolicy{
		RequireMfa: &models.MfaPolicy{
			Count:            ref.Of(int32(1)),
			NumAuthFactors:   &numAuthFactors,
			AllowedApprovers: ref.Of([]string{userResp.UserId}),
			AllowedMfaTypes:  ref.Of([]models.MfaType{CubeSignerMfaType()}),
		},
	}

	keyId, err := createSigningBlobKey(mfaPolicy, nil)
	require.NoError(t, err)
	defer deleteTestKey(t, testEnv.jsonClient, keyId)
	signMessage := "test message"

	signResp := signBlob(t, testEnv.jsonClient, signMessage, keyId)
	require.True(t, signResp.RequiresMfa())

	// test get mfa info
	mfaReq, err := testEnv.jsonClient.MfaGet(signResp.MfaRequired.Id)
	require.NoError(t, err)
	// there should be no receipts for unapproved requests
	require.Nil(t, GetReceipt(mfaReq))
	// Exactly one approver which is me
	require.Equal(t, 1, len(mfaReq.Status.AllowedApprovers))
	require.Equal(t, userResp.UserId, mfaReq.Status.AllowedApprovers[0])
	require.Zero(t, len(mfaReq.Status.ApprovedBy))
	// approve and confirm receipts
	approvalInfo, err := testEnv.jsonClient.MfaVoteCs(signResp.MfaRequired.Id, &models.MfaVoteCsParams{MfaVote: ref.Of(models.Approve)})
	require.NoError(t, err)
	require.NotNil(t, GetReceipt(approvalInfo))
	// Re-test approver info
	require.Equal(t, 1, len(approvalInfo.Status.ApprovedBy))
	// resubmit request and ensure we get a signed message
	signResp = signBlob(t, testEnv.jsonClient, signMessage, keyId, GetReceipt(approvalInfo))
	require.False(t, signResp.RequiresMfa())

	sig := signResp.ResponseData.Signature
	require.NotEmpty(t, sig)
	require.NoError(t, err)
}

func TestMultiAuthMfaSingleUserSign(t *testing.T) {
	// get user id
	resp, err := testEnv.jsonClient.AboutMe()
	require.NoError(t, err)
	userId := resp.UserId
	totalAuthFactors := int32(2)
	// test with multi auth factor single user
	mfaPolicyDetails := models.MfaPolicy{
		Count:            ref.Of(int32(1)),
		NumAuthFactors:   &totalAuthFactors,
		AllowedApprovers: ref.Of([]string{userId}),
		AllowedMfaTypes:  ref.Of([]models.MfaType{CubeSignerMfaType(), TotpMfaType()}),
	}
	keyId, err := createSigningBlobKey(RequireMfaPolicy{RequireMfa: &mfaPolicyDetails}, nil)
	require.NoError(t, err)
	defer deleteTestKey(t, testEnv.jsonClient, keyId)
	signMessage := "test message"

	signResp := signBlob(t, testEnv.jsonClient, signMessage, keyId)
	require.True(t, signResp.RequiresMfa())

	approvedReq, err := testEnv.jsonClient.MfaVoteCs(signResp.MfaRequired.Id, &models.MfaVoteCsParams{MfaVote: ref.Of(models.Approve)})
	require.Nil(t, GetReceipt(approvedReq))
	require.NoError(t, err)

	approvedReq, err = testEnv.jsonClient.MfaVoteTotp(signResp.MfaRequired.Id, &models.MfaVoteTotpParams{MfaVote: ref.Of(models.Approve)}, models.TotpApproveRequest{Code: getTotp()})
	require.NoError(t, err)

	require.NotNil(t, GetReceipt(approvedReq))

	// resubmit
	signResp = signBlob(t, testEnv.jsonClient, signMessage, keyId, GetReceipt(approvedReq))
	require.False(t, signResp.RequiresMfa())
}

func TestKeyUpdate(t *testing.T) {
	// get user id
	resp, err := testEnv.jsonClient.AboutMe()
	require.NoError(t, err)
	userId := resp.UserId
	signMessage := "testMessage"
	numAuthFactors := int32(1)
	// require Mfa but also set mfa for edits
	csMfaPolicy := models.EditPolicy{Mfa: &models.MfaPolicy{
		Count:            ref.Of(int32(1)),
		NumAuthFactors:   &numAuthFactors,
		AllowedApprovers: ref.Of([]string{userId}),
		AllowedMfaTypes:  ref.Of([]models.MfaType{CubeSignerMfaType()}),
	}}
	// policy to change to TOTP only
	totpMfaPolicy := models.EditPolicy{Mfa: &models.MfaPolicy{
		Count:            ref.Of(int32(1)),
		NumAuthFactors:   &numAuthFactors,
		AllowedApprovers: ref.Of([]string{userId}),
		AllowedMfaTypes:  ref.Of([]models.MfaType{TotpMfaType()}),
	}}
	keyId, err := createSigningBlobKey(RequireMfaPolicy{RequireMfa: csMfaPolicy.Mfa}, &totpMfaPolicy)
	require.NoError(t, err)

	// confirm that signing triggers CubeSigner mfa before change
	sign1Resp := signBlob(t, testEnv.jsonClient, signMessage, keyId)
	require.True(t, sign1Resp.RequiresMfa())
	mfaGetSign1, err := testEnv.jsonClient.MfaGet(sign1Resp.MfaRequired.Id)
	require.NoError(t, err)
	require.NotNil(t, mfaGetSign1.Status.AllowedMfaTypes)
	allowedTypes := *mfaGetSign1.Status.AllowedMfaTypes
	require.Equal(t, CubeSignerMfaType(), allowedTypes[0])

	// attempt to change sign policy to totp as well
	updateRequest := models.UpdateKeyRequest{
		Policy: ref.Of([]interface{}{
			RequireMfaPolicy{
				RequireMfa: totpMfaPolicy.Mfa,
			},
			allowRawBlobSigningPolicy,
		}),
	}
	// should trigger a totp mfa
	keyUpdateResp, err := testEnv.jsonClient.UpdateKey(keyId, updateRequest)
	require.NoError(t, err)
	require.True(t, keyUpdateResp.RequiresMfa())

	// Get mfa details to check required type
	mfaGetResp, err := testEnv.jsonClient.MfaGet(keyUpdateResp.MfaRequired.Id)
	require.NoError(t, err)
	require.NotNil(t, mfaGetResp.Status.AllowedMfaTypes)
	allowedTypes = *mfaGetResp.Status.AllowedMfaTypes
	require.Equal(t, TotpMfaType(), allowedTypes[0])
	require.Nil(t, GetReceipt(mfaGetResp))

	// Try to approve with Cs, should fail
	_, err = testEnv.jsonClient.MfaVoteCs(keyUpdateResp.MfaRequired.Id, &models.MfaVoteCsParams{MfaVote: ref.Of(models.Approve)})
	require.NotNil(t, err)
	require.True(t, strings.Contains(err.Error(), "MfaTypeNotAllowed"))

	// generate otp
	totpSecret := os.Getenv("TOTP_SECRET")
	answerCode, err := totp.GenerateCode(totpSecret, time.Now())
	require.NoError(t, err)
	// approve with Totp to change
	approvalResp, err := testEnv.jsonClient.MfaVoteTotp(keyUpdateResp.MfaRequired.Id, &models.MfaVoteTotpParams{MfaVote: ref.Of(models.Approve)}, models.TotpApproveRequest{Code: answerCode})
	require.NoError(t, err)
	require.NotNil(t, GetReceipt(approvalResp))
	// resubmit update key request
	keyUpdateResp, err = testEnv.jsonClient.UpdateKey(keyId, updateRequest, GetReceipt(approvalResp))
	require.NoError(t, err)
	require.False(t, keyUpdateResp.RequiresMfa())

	// attempt sign again to check type of Mfa required
	sign2Resp := signBlob(t, testEnv.jsonClient, signMessage, keyId)
	require.True(t, sign2Resp.RequiresMfa())
	mfaGetSign2, err := testEnv.jsonClient.MfaGet(sign2Resp.MfaRequired.Id)
	require.NoError(t, err)
	require.NotNil(t, mfaGetSign2.Status.AllowedMfaTypes)
	allowedTypes = *mfaGetSign2.Status.AllowedMfaTypes
	require.Equal(t, TotpMfaType(), allowedTypes[0])

	// delete key
	deleteResp, err := testEnv.jsonClient.DeleteKey(keyId)
	require.NoError(t, err)
	require.True(t, deleteResp.RequiresMfa())
	// approve with totp and resubmit
	totpSecret = os.Getenv("TOTP_SECRET")
	answerCode, err = totp.GenerateCode(totpSecret, time.Now())
	require.NoError(t, err)
	approvalResp, err = testEnv.jsonClient.MfaVoteTotp(deleteResp.MfaRequired.Id, &models.MfaVoteTotpParams{MfaVote: ref.Of(models.Approve)}, models.TotpApproveRequest{Code: answerCode})
	require.NoError(t, err)
	require.NotNil(t, GetReceipt(approvalResp))

	deleteResp, err = testEnv.jsonClient.DeleteKey(keyId, GetReceipt(approvalResp))
	require.NoError(t, err)
	require.False(t, deleteResp.RequiresMfa())
}

func TestSessionFileUpdate(t *testing.T) {
	authLifeTime := int64(25)
	graceLifetime := int64(0)
	tempFile := "tempfile.json"
	// Create a short lived session to trigger auto refresh
	respSession, err := testEnv.jsonClient.CreateSession("Test session", []models.Scope{"manage:*"}, &Lifetimes{
		AuthLifetime:  &authLifeTime,
		GraceLifetime: &graceLifetime,
	})
	require.NoError(t, err)
	writeSessionToFile(respSession.ResponseData, tempFile)
	defer os.Remove(tempFile)

	// manage this session
	newManager, err := NewJsonSessionManager(&tempFile)
	require.NoError(t, err)
	newClient, err := NewApiClient(newManager)
	require.NoError(t, err)

	// trigger refresh. The session file should update
	token1, err := newManager.Token()
	require.NoError(t, err)
	// check that token1 is ok
	_, err = newClient.AboutMe()
	require.NoError(t, err)

	// make a new manager and client for same file.
	newManager2, err := NewJsonSessionManager(&tempFile)
	require.NoError(t, err)
	newClient2, err := NewApiClient(newManager2)
	require.NoError(t, err)

	// test it works
	token2, err := newManager2.Token()
	require.NoError(t, err)
	_, err = newClient2.AboutMe()
	require.NoError(t, err)

	// tokens must be different because of file update.
	require.NotEqual(t, token1, token2)
}

func TestAboutMe(t *testing.T) {
	resp, err := testEnv.jsonClient.AboutMe()
	require.NoError(t, err)
	// test reading user id
	value := resp.UserId
	require.NotEqual(t, "", value)
	// check if totp is configured in Mfa
	mfaConf, err := resp.Mfa[0].AsConfiguredMfaTotp()
	require.NoError(t, err)
	// require checks types, so casting is needed
	require.Equal(t, "totp", string(mfaConf.Type))
	// but values should be the equal too
	if mfaConf.Type != "totp" {
		require.FailNow(t, "mfaConf not equal to expected value")
	}
}

func TestGetOrg(t *testing.T) {
	orgInfo, err := testEnv.jsonClient.GetOrg()
	require.NoError(t, err)
	// test org Id is same
	require.Equal(t, testEnv.jsonClient.Manager.Metadata().OrgID, orgInfo.OrgId)
}

func TestAutoRefreshSimple(t *testing.T) {
	// 25s is less than expiration buffer of 30s and will trigger refresh
	authLifeTimeCases := [2]int64{25, 300}
	graceLifetime := int64(0)
	for _, authLifeTime := range authLifeTimeCases {
		// Create a session
		respSession, err := testEnv.jsonClient.CreateSession("Test session", []models.Scope{"manage:*"}, &Lifetimes{
			AuthLifetime:  &authLifeTime,
			GraceLifetime: &graceLifetime,
		})
		require.NoError(t, err)
		memManager := NewMemorySessionManager(respSession.ResponseData)

		client, err := NewApiClient(memManager)
		require.NoError(t, err)
		_, err = client.AboutMe()
		require.NoError(t, err)

		// if session is expired, auto-refresh should still make it work
		_, err = client.AboutMe()
		require.NoError(t, err)
	}
}

// Test concurrent client API calls with a short-lived
// session. The session should be auto-refreshed every time,
// and API calls should continue to function as normal.
func TestConcurrentCalls(t *testing.T) {
	authLifeTime := int64(35)
	graceLifeTime := int64(0)

	// Create a short-lived session to trigger auto refreshes
	respSession, err := testEnv.jsonClient.CreateSession("Test short session", []models.Scope{"manage:*"}, &Lifetimes{
		AuthLifetime:  &authLifeTime,
		GraceLifetime: &graceLifeTime,
	})
	require.NoError(t, err)
	// test concurrent calls with memory manager
	memManager := NewMemorySessionManager(respSession.ResponseData)
	concurrentCallsSingleClient(t, memManager)
	concurrentCallsMultipleClients(t, memManager)

	// Create a session and write to temp file
	respSession, err = testEnv.jsonClient.CreateSession("Test short session", []models.Scope{"manage:*"}, &Lifetimes{
		AuthLifetime:  &authLifeTime,
		GraceLifetime: &graceLifeTime,
	})
	require.NoError(t, err)
	tempFilePath := "tempfile.json"
	writeSessionToFile(respSession.ResponseData, tempFilePath)
	defer os.Remove(tempFilePath)

	// test concurrent calls with json manager
	jsonManager, err := NewJsonSessionManager(&tempFilePath)
	require.NoError(t, err)
	concurrentCallsSingleClient(t, jsonManager)
	concurrentCallsMultipleClients(t, jsonManager)
}

// Execute concurrent calls to multiple endpoints using a single client
// for all go routines.
func concurrentCallsSingleClient(t *testing.T, manager SessionManager) {
	client, err := NewApiClient(manager)
	require.NoError(t, err)

	var wg sync.WaitGroup

	// call different endpoints concurrently and repeatedly
	for range 30 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			// random delay up to 500 ms
			n := rand.IntN(500)
			time.Sleep(time.Duration(n) * time.Millisecond)
			_, err := client.AboutMe()
			require.NoError(t, err)
		}()
		go func() {
			defer wg.Done()
			// random delay up to 500 ms
			n := rand.IntN(500)
			time.Sleep(time.Duration(n) * time.Millisecond)
			_, err := client.GetOrg()
			require.NoError(t, err)
		}()
		go func() {
			defer wg.Done()
			// random delay up to 500 ms
			n := rand.IntN(500)
			time.Sleep(time.Duration(n) * time.Millisecond)
			_, err := client.ListSessions(nil)
			require.NoError(t, err)
		}()
	}

	wg.Wait()
}

// Execute concurrent calls to multiple endpoints using multiple clients.
// Each go routine creates its own client.
func concurrentCallsMultipleClients(t *testing.T, manager SessionManager) {
	var wg sync.WaitGroup
	// call different endpoints concurrently and repeatedly
	for range 30 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			client, err := NewApiClient(manager)
			require.NoError(t, err)
			// random delay up to 500 ms
			n := rand.IntN(500)
			time.Sleep(time.Duration(n) * time.Millisecond)
			_, err = client.AboutMe()
			require.NoError(t, err)
		}()
		go func() {
			defer wg.Done()
			client, err := NewApiClient(manager)
			require.NoError(t, err)
			// random delay up to 500 ms
			n := rand.IntN(500)
			time.Sleep(time.Duration(n) * time.Millisecond)
			_, err = client.GetOrg()
			require.NoError(t, err)
		}()
		go func() {
			defer wg.Done()
			client, err := NewApiClient(manager)
			require.NoError(t, err)
			// random delay up to 500 ms
			n := rand.IntN(500)
			time.Sleep(time.Duration(n) * time.Millisecond)
			_, err = client.ListSessions(nil)
			require.NoError(t, err)
		}()
	}

	wg.Wait()
}

// TODO: Expand with types later to include more endpoints
// with request bodies and check responses.
func TestGeneratedGets(t *testing.T) {
	_, err := testEnv.jsonClient.MfaList()
	require.NoError(t, err)

	params := models.ListRolesParams{
		PageSize:  ref.Of(int32(100)),
		Summarize: ref.Of(true),
	}
	_, err = testEnv.jsonClient.ListRoles(&params)
	require.NoError(t, err)

	sessionId := testEnv.jsonClient.Manager.Metadata().SessionID
	_, err = testEnv.jsonClient.GetSession(sessionId)
	require.NoError(t, err)

	_, err = testEnv.jsonClient.ListKeysInOrg(nil)
	require.NoError(t, err)

	listPoliciesParams := models.ListPoliciesParams{
		PageSize: ref.Of(int32(10)),
	}
	_, err = testEnv.jsonClient.ListPolicies(&listPoliciesParams)
	require.NoError(t, err)

	listContactsParams := models.ListContactsParams{
		PageSize: ref.Of(int32(100)),
	}
	_, err = testEnv.jsonClient.ListContacts(&listContactsParams)
	require.NoError(t, err)

	_, err = testEnv.jsonClient.Counts()
	require.NoError(t, err)

	_, err = testEnv.jsonClient.ListOidcIdentities()
	require.NoError(t, err)
}

func TestPublicOrgInfo(t *testing.T) {
	testOrg := testEnv.jsonSessionManager.Metadata().OrgID
	// test env
	env := EnvInterface{Spec: &Spec{
		SignerApiRoot: testEnv.jsonClient.RootUrl,
	}}

	publicOrgInfo, err := PublicOrgInfo(env, testOrg)
	require.NoError(t, err)
	require.Equal(t, testOrg, publicOrgInfo.OrgId)
}

func TestEmailMyOrgs(t *testing.T) {
	// skip in CI. This endpoint has a strict rate limit
	if os.Getenv("CI") != "" {
		t.Skip("Skipping test in CI environment")
	}

	testUser, err := testEnv.jsonClient.AboutMe()
	require.NoError(t, err)
	// test env
	env := EnvInterface{Spec: &Spec{
		SignerApiRoot: testEnv.jsonClient.RootUrl,
	}}

	_, err = EmailMyOrgs(env, models.EmailMyOrgsParams{
		Email: *testUser.Email,
	})
	require.NoError(t, err)
}

// Test Oidc endpoints including Login and Registration flows
func TestOidc(t *testing.T) {
	oidcToken := os.Getenv("OIDC_TOKEN")
	require.NotNil(t, oidcToken)

	testOrg := testEnv.jsonSessionManager.Metadata().OrgID
	rootUrl := testEnv.jsonClient.RootUrl

	// test env
	env := EnvInterface{Spec: &Spec{
		SignerApiRoot: rootUrl,
	}}

	// test UserOrgs
	resp, err := UserOrgs(env, oidcToken)
	require.NoError(t, err)
	require.Equal(t, testOrg, resp.Orgs[0].OrgId)

	// test OidcLogin
	oidcAuthResp, err := OidcAuth(env, testOrg, oidcToken, models.OidcLoginRequest{
		Scopes: []models.Scope{"manage:*"},
	})
	require.NoError(t, err)
	require.False(t, oidcAuthResp.RequiresMfa())

	// create an Oidc proof
	proof, err := CreateProofOidc(env, testOrg, oidcToken)
	require.NoError(t, err)

	// create a user using proof
	userCreateResp, err := testEnv.jsonClient.CreateOidcUser(models.AddThirdPartyUserRequest{
		Proof: proof,
		Role:  models.Alien,
	})
	require.NoError(t, err)
	require.NotEmpty(t, userCreateResp.UserId)

	// clean-up delete the user
	_, err = testEnv.jsonClient.DeleteOidcUser(models.OidcIdentity{
		Iss: proof.Identity.Iss,
		Sub: proof.Identity.Sub,
	})
	require.NoError(t, err)
}

func TestEvmSign(t *testing.T) {
	createKeyRequest := models.CreateKeyRequest{KeyType: models.SecpEthAddr, Count: 1}
	keysInfo, err := testEnv.jsonClient.CreateKey(createKeyRequest)
	require.NoError(t, err)

	// Create signing request
	tx := models.Transaction{}
	// EIP-1559 typed transaction
	err = tx.FromTypedTransactionEip1559(models.TypedTransactionEip1559{
		To:                   ref.Of("0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b"),
		Type:                 "0x02",
		Gas:                  ref.Of("0x61a80"),
		MaxFeePerGas:         ref.Of("0x2540be400"),
		MaxPriorityFeePerGas: ref.Of("0x3b9aca00"),
		Nonce:                ref.Of("0"),
		Value:                ref.Of("0x100"),
	})
	require.NoError(t, err)
	resp, err := testEnv.jsonClient.EvmSign(keysInfo.Keys[0].MaterialId, models.Eth1SignRequest{
		ChainId: int64(1),
		Tx:      tx,
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.ResponseData.RlpSignedTx)
}

func TestOrgPolicy(t *testing.T) {
	orgInfo, err := testEnv.jsonClient.GetOrg()
	require.NoError(t, err)
	oldPolicy := orgInfo.Policy // to restore later

	oidcPolicy := map[string]interface{}{
		"OidcAuthSources": map[string][]string{
			"https://shim.oauth2.cubist.dev/email-otp": {
				testEnv.jsonSessionManager.Metadata().OrgID,
			},
		},
	}
	updateResp, err := testEnv.jsonClient.UpdateOrg(models.UpdateOrgRequest{
		Policy: ref.Of([]map[string]interface{}{oidcPolicy}),
	})
	require.NoError(t, err)
	require.NotNil(t, updateResp.Policy)
	require.NotEmpty(t, *updateResp.Policy)

	// reset policy
	_, err = testEnv.jsonClient.UpdateOrg(models.UpdateOrgRequest{
		Policy: oldPolicy,
	})
	require.NoError(t, err)
}

func TestNamedPolicies(t *testing.T) {
	policyName := "evm_policy_test"

	policyInfo, err := testEnv.jsonClient.CreatePolicy(models.CreatePolicyRequest{
		Name:       policyName,
		PolicyType: models.Key,
		Rules: []interface{}{
			map[string]string{"TxValueLimit": "0x10"},
		},
	})
	defer func() {
		if policyInfo != nil {
			_, err := testEnv.jsonClient.DeletePolicy(policyInfo.PolicyId)
			require.NoError(t, err)
		}
	}()
	require.NoError(t, err)

	_, err = testEnv.jsonClient.UpdatePolicy(policyInfo.PolicyId, models.UpdatePolicyRequest{
		Rules: ref.Of([]interface{}{
			map[string]string{
				"TxValueLimit": "0x10",
			},
			map[string]interface{}{
				"IfErc20Tx": map[string]interface{}{
					"transfer_limits": []map[string]string{
						{
							"limit": "0x186A0",
						},
					},
				},
			},
		}),
	})
	require.NoError(t, err)

	// get v1 of policy
	v1, err := testEnv.jsonClient.GetPolicy(policyInfo.PolicyId, "v1")
	require.NoError(t, err)
	require.NotEmpty(t, v1.Name)

	current, err := testEnv.jsonClient.GetPolicy(policyInfo.PolicyId, "latest")
	require.NoError(t, err)
	require.NotEmpty(t, current.Name)

	createKeyRequest := models.CreateKeyRequest{KeyType: models.SecpEthAddr, Count: 1}
	keysInfo, err := testEnv.jsonClient.CreateKey(createKeyRequest)
	require.NoError(t, err)
	keyId := keysInfo.Keys[0].KeyId
	defer deleteTestKey(t, testEnv.jsonClient, keyId)

	// add AllowRawBlobSigning policy to begin
	baseKeyInfo, err := testEnv.jsonClient.UpdateKey(keyId, models.UpdateKeyRequest{
		Policy: ref.Of([]interface{}{"AllowRawBlobSigning"}),
	})
	require.NoError(t, err)
	require.Equal(t, baseKeyInfo.ResponseData.Policy[0].(string), "AllowRawBlobSigning")

	// fetch original policy to append to
	keyInfo, err := testEnv.jsonClient.GetKeyInOrg(keyId)
	require.NoError(t, err)
	previousPolicy := keyInfo.Policy

	// update policy
	updatedPolicy := append(previousPolicy, "evm_policy_test/latest")
	updatedInfo, err := testEnv.jsonClient.UpdateKey(keyId, models.UpdateKeyRequest{
		Policy: &updatedPolicy,
	})
	require.NoError(t, err)
	require.NotEmpty(t, updatedInfo.ResponseData.KeyId)

	// check both policies now exist in key
	flagBlob := false
	flagEvm := false
	for _, policy := range updatedInfo.ResponseData.Policy {
		if policy.(string) == "AllowRawBlobSigning" {
			flagBlob = true
		}
		if policy.(string) == policyInfo.PolicyId+"/latest" {
			flagEvm = true
		}
	}
	require.True(t, flagBlob && flagEvm)
}

func TestSpecEnvs(t *testing.T) {
	envInf := env.Gamma
	require.NotNil(t, envInf.Spec.SignerApiRoot)

	envInf = env.Beta
	require.NotNil(t, envInf.Spec.SignerApiRoot)

	envInf = env.Prod
	require.NotNil(t, envInf.Spec.SignerApiRoot)
}

func TestSessionData(t *testing.T) {
	sessionFile, err := utils.GetDefaultSessionFilePath()
	require.NoError(t, err)

	sessionData, err := GetSessionFromFile(sessionFile)
	require.NoError(t, err)

	require.NotEqual(t, nil, sessionData.SessionInfo)
	require.NotEqual(t, "", sessionData.SessionInfo.SessionId)

	require.NotEqual(t, nil, sessionData.Env)
	require.NotEqual(t, "", sessionData.Env.Spec.SignerApiRoot)

	require.NotEqual(t, "", sessionData.Token)
}
