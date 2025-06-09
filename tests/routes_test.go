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
	require.Nil(t, err)
	require.False(t, deleteResp.RequiresMfa())
}

func signBlob(t *testing.T, client *ApiClient, message string, keyId string, receipts ...*MfaReceipt) *CubeSignerResponse[models.SignResponse] {
	signRequestBody := models.BlobSignRequest{
		MessageBase64: base64.StdEncoding.EncodeToString([]byte(message)),
	}
	// try signing
	signResp, err := client.BlobSign(keyId, signRequestBody, receipts...)
	require.Nil(t, err)

	return signResp
}

func TestSessionGet(t *testing.T) {
	params := models.ListSessionsParams{
		PageSize: ref.Of(int32(1000)),
	}
	response, err := testEnv.jsonClient.ListSessions(&params)
	require.Nil(t, err)

	for len(response.Sessions) == 0 && response.LastEvaluatedKey != nil {
		params.PageStart = response.LastEvaluatedKey
		response, err = testEnv.jsonClient.ListSessions(&params)
		require.Nil(t, err)
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
	require.Nil(t, err)
	// Create a session
	respSession, err := testEnv.jsonClient.CreateSession("Test session", []models.Scope{"manage:*"}, nil)
	require.Nil(t, err)

	// make a new manager
	memManager := NewMemorySessionManager(respSession.ResponseData)
	client, err := NewApiClient(memManager)
	require.Nil(t, err)

	// test this client
	resp2, err := client.AboutMe()
	require.Nil(t, err)
	require.Equal(t, resp1.UserId, resp2.UserId)
}

func TestCreateSessionMfa(t *testing.T) {
	// Create a session that requires MFA
	lifetimes := &Lifetimes{
		ExtendLifetimes: ref.Of(true),
	}
	sessionResp, err := testEnv.jsonClient.CreateSession("Test session", []models.Scope{"manage:*"}, lifetimes)
	require.Nil(t, err)
	require.True(t, sessionResp.RequiresMfa())

	// try approve with cubesigner session: should fail
	_, err = testEnv.jsonClient.MfaVoteCs(sessionResp.MfaRequired.Id, &models.MfaVoteCsParams{MfaVote: ref.Of(models.Approve)})
	require.NotNil(t, err)
	require.True(t, strings.Contains(err.Error(), "MfaTypeNotAllowed"))

	// approve mfa
	totpResp, err := testEnv.jsonClient.MfaVoteTotp(sessionResp.MfaRequired.Id, &models.MfaVoteTotpParams{MfaVote: ref.Of(models.Approve)}, models.TotpApproveRequest{Code: getTotp()})
	require.Nil(t, err)
	require.NotNil(t, GetReceipt(totpResp))
	// resubmit
	sessionResp, err = testEnv.jsonClient.CreateSession("Test session", []models.Scope{"manage:*"}, lifetimes, GetReceipt(totpResp))
	require.Nil(t, err)
	// ensure no mfa in response
	require.False(t, sessionResp.RequiresMfa())

	// use this session
	memManager := NewMemorySessionManager(sessionResp.ResponseData)
	newClient, err := NewApiClient(memManager)
	require.Nil(t, err)

	_, err = newClient.AboutMe()
	require.Nil(t, err)
}

// Test that error is returned as expected
// instead of MfaRequired response.
func TestSignFailure(t *testing.T) {
	// get user id
	userResp, err := testEnv.jsonClient.AboutMe()
	require.Nil(t, err)
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
	require.Nil(t, err)

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
	require.Nil(t, err)

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
	require.Nil(t, err)
	defer deleteTestKey(t, testEnv.jsonClient, keyId)
	signMessage := "test message"

	signResp := signBlob(t, testEnv.jsonClient, signMessage, keyId)
	require.True(t, signResp.RequiresMfa())

	// test get mfa info
	mfaReq, err := testEnv.jsonClient.MfaGet(signResp.MfaRequired.Id)
	require.Nil(t, err)
	// there should be no receipts for unapproved requests
	require.Nil(t, GetReceipt(mfaReq))
	// Exactly one approver which is me
	require.Equal(t, 1, len(mfaReq.Status.AllowedApprovers))
	require.Equal(t, userResp.UserId, mfaReq.Status.AllowedApprovers[0])
	require.Zero(t, len(mfaReq.Status.ApprovedBy))
	// approve and confirm receipts
	approvalInfo, err := testEnv.jsonClient.MfaVoteCs(signResp.MfaRequired.Id, &models.MfaVoteCsParams{MfaVote: ref.Of(models.Approve)})
	require.Nil(t, err)
	require.NotNil(t, GetReceipt(approvalInfo))
	// Re-test approver info
	require.Equal(t, 1, len(approvalInfo.Status.ApprovedBy))
	// resubmit request and ensure we get a signed message
	signResp = signBlob(t, testEnv.jsonClient, signMessage, keyId, GetReceipt(approvalInfo))
	require.False(t, signResp.RequiresMfa())

	sig := signResp.ResponseData.Signature
	require.NotEmpty(t, sig)
	require.Nil(t, err)
}

func TestMultiAuthMfaSingleUserSign(t *testing.T) {
	// get user id
	resp, err := testEnv.jsonClient.AboutMe()
	require.Nil(t, err)
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
	require.Nil(t, err)
	defer deleteTestKey(t, testEnv.jsonClient, keyId)
	signMessage := "test message"

	signResp := signBlob(t, testEnv.jsonClient, signMessage, keyId)
	require.True(t, signResp.RequiresMfa())

	approvedReq, err := testEnv.jsonClient.MfaVoteCs(signResp.MfaRequired.Id, &models.MfaVoteCsParams{MfaVote: ref.Of(models.Approve)})
	require.Nil(t, GetReceipt(approvedReq))
	require.Nil(t, err)

	approvedReq, err = testEnv.jsonClient.MfaVoteTotp(signResp.MfaRequired.Id, &models.MfaVoteTotpParams{MfaVote: ref.Of(models.Approve)}, models.TotpApproveRequest{Code: getTotp()})
	require.Nil(t, err)

	require.NotNil(t, GetReceipt(approvedReq))

	// resubmit
	signResp = signBlob(t, testEnv.jsonClient, signMessage, keyId, GetReceipt(approvedReq))
	require.False(t, signResp.RequiresMfa())
}

// This test is interactive and should be skipped in test
// suite. It requires the user to fetch otp from email
// and enter it as a response.
//
// Running this test with `go test` will not work as
// `go test` disables StdIn. Compiling the test first
// to a binary and then running it works fine. i.e.,
// `go test -c ./... -v` compiles all tests.
// `./<testBinaryPrefix>.test -test.run TestMfaSignEmail`
// runs this test.
func TestMfaSignEmail(t *testing.T) {
	// get user id
	resp, err := testEnv.jsonClient.AboutMe()
	require.Nil(t, err)
	userId := resp.UserId
	numAuthFactors := int32(1)
	// test single auth factor with email
	mfaPolicyDetails := models.MfaPolicy{
		Count:            ref.Of(int32(1)),
		NumAuthFactors:   &numAuthFactors,
		AllowedApprovers: ref.Of([]string{userId}),
		AllowedMfaTypes:  ref.Of([]models.MfaType{EmailOtpMfaType()}),
	}

	keyId, err := createSigningBlobKey(RequireMfaPolicy{RequireMfa: &mfaPolicyDetails}, nil)
	require.Nil(t, err)
	defer deleteTestKey(t, testEnv.jsonClient, keyId)
	signMessage := "test message"

	// try signing
	signResp := signBlob(t, testEnv.jsonClient, signMessage, keyId)
	require.True(t, signResp.RequiresMfa())

	// vote approval
	emailChallenge, err := testEnv.jsonClient.MfaVoteEmailInit(signResp.MfaRequired.Id, models.Approve)
	require.Nil(t, err)
	fmt.Println("Enter email otp:")
	var emailOtp string
	_, err = fmt.Scan(&emailOtp)
	require.Nil(t, err)
	// answer challenge
	approvalInfo, err := emailChallenge.Answer(emailOtp)
	require.Nil(t, err)
	require.NotNil(t, GetReceipt(approvalInfo))

	// resubmit
	signResp = signBlob(t, testEnv.jsonClient, signMessage, keyId, GetReceipt(approvalInfo))
	require.False(t, signResp.RequiresMfa())
}

func TestKeyUpdate(t *testing.T) {
	// get user id
	resp, err := testEnv.jsonClient.AboutMe()
	require.Nil(t, err)
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
	require.Nil(t, err)

	// confirm that signing triggers CubeSigner mfa before change
	sign1Resp := signBlob(t, testEnv.jsonClient, signMessage, keyId)
	require.True(t, sign1Resp.RequiresMfa())
	mfaGetSign1, err := testEnv.jsonClient.MfaGet(sign1Resp.MfaRequired.Id)
	require.Nil(t, err)
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
	require.Nil(t, err)
	require.True(t, keyUpdateResp.RequiresMfa())

	// Get mfa details to check required type
	mfaGetResp, err := testEnv.jsonClient.MfaGet(keyUpdateResp.MfaRequired.Id)
	require.Nil(t, err)
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
	require.Nil(t, err)
	// approve with Totp to change
	approvalResp, err := testEnv.jsonClient.MfaVoteTotp(keyUpdateResp.MfaRequired.Id, &models.MfaVoteTotpParams{MfaVote: ref.Of(models.Approve)}, models.TotpApproveRequest{Code: answerCode})
	require.Nil(t, err)
	require.NotNil(t, GetReceipt(approvalResp))
	// resubmit update key request
	keyUpdateResp, err = testEnv.jsonClient.UpdateKey(keyId, updateRequest, GetReceipt(approvalResp))
	require.Nil(t, err)
	require.False(t, keyUpdateResp.RequiresMfa())

	// attempt sign again to check type of Mfa required
	sign2Resp := signBlob(t, testEnv.jsonClient, signMessage, keyId)
	require.True(t, sign2Resp.RequiresMfa())
	mfaGetSign2, err := testEnv.jsonClient.MfaGet(sign2Resp.MfaRequired.Id)
	require.Nil(t, err)
	require.NotNil(t, mfaGetSign2.Status.AllowedMfaTypes)
	allowedTypes = *mfaGetSign2.Status.AllowedMfaTypes
	require.Equal(t, TotpMfaType(), allowedTypes[0])

	// delete key
	deleteResp, err := testEnv.jsonClient.DeleteKey(keyId)
	require.Nil(t, err)
	require.True(t, deleteResp.RequiresMfa())
	// approve with totp and resubmit
	totpSecret = os.Getenv("TOTP_SECRET")
	answerCode, err = totp.GenerateCode(totpSecret, time.Now())
	require.Nil(t, err)
	approvalResp, err = testEnv.jsonClient.MfaVoteTotp(deleteResp.MfaRequired.Id, &models.MfaVoteTotpParams{MfaVote: ref.Of(models.Approve)}, models.TotpApproveRequest{Code: answerCode})
	require.Nil(t, err)
	require.NotNil(t, GetReceipt(approvalResp))

	deleteResp, err = testEnv.jsonClient.DeleteKey(keyId, GetReceipt(approvalResp))
	require.Nil(t, err)
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
	require.Nil(t, err)
	writeSessionToFile(respSession.ResponseData, tempFile)
	defer os.Remove(tempFile)

	// manage this session
	newManager, err := NewJsonSessionManager(&tempFile)
	require.Nil(t, err)
	newClient, err := NewApiClient(newManager)
	require.Nil(t, err)

	// trigger refresh. The session file should update
	token1, err := newManager.Token()
	require.Nil(t, err)
	// check that token1 is ok
	_, err = newClient.AboutMe()
	require.Nil(t, err)

	// make a new manager and client for same file.
	newManager2, err := NewJsonSessionManager(&tempFile)
	require.Nil(t, err)
	newClient2, err := NewApiClient(newManager2)
	require.Nil(t, err)

	// test it works
	token2, err := newManager2.Token()
	require.Nil(t, err)
	_, err = newClient2.AboutMe()
	require.Nil(t, err)

	// tokens must be different because of file update.
	require.NotEqual(t, token1, token2)
}

func TestAboutMe(t *testing.T) {
	resp, err := testEnv.jsonClient.AboutMe()
	require.Nil(t, err)
	// test reading user id
	value := resp.UserId
	require.NotEqual(t, "", value)
	// check if totp is configured in Mfa
	mfaConf, err := resp.Mfa[0].AsConfiguredMfaTotp()
	require.Nil(t, err)
	// require checks types, so casting is needed
	require.Equal(t, "totp", string(mfaConf.Type))
	// but values should be the equal too
	if mfaConf.Type != "totp" {
		require.FailNow(t, "mfaConf not equal to expected value")
	}
}

func TestGetOrg(t *testing.T) {
	orgInfo, err := testEnv.jsonClient.GetOrg()
	require.Nil(t, err)
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
		require.Nil(t, err)
		memManager := NewMemorySessionManager(respSession.ResponseData)

		client, err := NewApiClient(memManager)
		require.Nil(t, err)
		_, err = client.AboutMe()
		require.Nil(t, err)

		// if session is expired, auto-refresh should still make it work
		_, err = client.AboutMe()
		require.Nil(t, err)
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
	require.Nil(t, err)
	// test concurrent calls with memory manager
	memManager := NewMemorySessionManager(respSession.ResponseData)
	concurrentCallsSingleClient(t, memManager)
	concurrentCallsMultipleClients(t, memManager)

	// Create a session and write to temp file
	respSession, err = testEnv.jsonClient.CreateSession("Test short session", []models.Scope{"manage:*"}, &Lifetimes{
		AuthLifetime:  &authLifeTime,
		GraceLifetime: &graceLifeTime,
	})
	require.Nil(t, err)
	tempFilePath := "tempfile.json"
	writeSessionToFile(respSession.ResponseData, tempFilePath)
	defer os.Remove(tempFilePath)

	// test concurrent calls with json manager
	jsonManager, err := NewJsonSessionManager(&tempFilePath)
	require.Nil(t, err)
	concurrentCallsSingleClient(t, jsonManager)
	concurrentCallsMultipleClients(t, jsonManager)
}

// Execute concurrent calls to multiple endpoints using a single client
// for all go routines.
func concurrentCallsSingleClient(t *testing.T, manager SessionManager) {
	client, err := NewApiClient(manager)
	require.Nil(t, err)

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
			require.Nil(t, err)
		}()
		go func() {
			defer wg.Done()
			// random delay up to 500 ms
			n := rand.IntN(500)
			time.Sleep(time.Duration(n) * time.Millisecond)
			_, err := client.GetOrg()
			require.Nil(t, err)
		}()
		go func() {
			defer wg.Done()
			// random delay up to 500 ms
			n := rand.IntN(500)
			time.Sleep(time.Duration(n) * time.Millisecond)
			_, err := client.ListSessions(nil)
			require.Nil(t, err)
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
			require.Nil(t, err)
			// random delay up to 500 ms
			n := rand.IntN(500)
			time.Sleep(time.Duration(n) * time.Millisecond)
			_, err = client.AboutMe()
			require.Nil(t, err)
		}()
		go func() {
			defer wg.Done()
			client, err := NewApiClient(manager)
			require.Nil(t, err)
			// random delay up to 500 ms
			n := rand.IntN(500)
			time.Sleep(time.Duration(n) * time.Millisecond)
			_, err = client.GetOrg()
			require.Nil(t, err)
		}()
		go func() {
			defer wg.Done()
			client, err := NewApiClient(manager)
			require.Nil(t, err)
			// random delay up to 500 ms
			n := rand.IntN(500)
			time.Sleep(time.Duration(n) * time.Millisecond)
			_, err = client.ListSessions(nil)
			require.Nil(t, err)
		}()
	}

	wg.Wait()
}

// TODO: Expand with types later to include more endpoints
// with request bodies and check responses.
func TestGeneratedGets(t *testing.T) {
	_, err := testEnv.jsonClient.MfaList()
	require.Nil(t, err)

	params := models.ListRolesParams{
		PageSize:  ref.Of(int32(100)),
		Summarize: ref.Of(true),
	}
	_, err = testEnv.jsonClient.ListRoles(&params)
	require.Nil(t, err)

	sessionId := testEnv.jsonClient.Manager.Metadata().SessionID
	_, err = testEnv.jsonClient.GetSession(sessionId)
	require.Nil(t, err)

	_, err = testEnv.jsonClient.ListKeysInOrg(nil)
	require.Nil(t, err)

	listPoliciesParams := models.ListPoliciesParams{
		PageSize: ref.Of(int32(10)),
	}
	_, err = testEnv.jsonClient.ListPolicies(&listPoliciesParams)
	require.Nil(t, err)

	listContactsParams := models.ListContactsParams{
		PageSize: ref.Of(int32(100)),
	}
	_, err = testEnv.jsonClient.ListContacts(&listContactsParams)
	require.Nil(t, err)

	_, err = testEnv.jsonClient.Counts()
	require.Nil(t, err)

	_, err = testEnv.jsonClient.ListOidcIdentities()
	require.Nil(t, err)
}

func TestSessionlessClient(t *testing.T) {
	testOrg := testEnv.jsonSessionManager.Metadata().OrgID
	testUser, err := testEnv.jsonClient.AboutMe()
	require.Nil(t, err)

	// test env
	env := EnvInterface{Spec: &Spec{
		SignerApiRoot: testEnv.jsonClient.RootUrl,
	}}

	_, err = EmailMyOrgs(env, models.EmailMyOrgsParams{
		Email: *testUser.Email,
	})
	require.Nil(t, err)

	publicOrgInfo, err := PublicOrgInfo(env, testOrg)
	require.Nil(t, err)
	require.Equal(t, testOrg, publicOrgInfo.OrgId)

	publicOrgInfo, err = PublicOrgInfo(env, testOrg)
	require.Nil(t, err)
	require.Equal(t, testOrg, publicOrgInfo.OrgId)
}

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
	require.Nil(t, err)
	require.Equal(t, testOrg, resp.Orgs[0].OrgId)

	// test OidcLogin
	oidcAuthResp, err := OidcAuth(env, testOrg, oidcToken, models.OidcLoginRequest{
		Scopes: []models.Scope{"manage:*"},
	})
	require.Nil(t, err)
	require.False(t, oidcAuthResp.RequiresMfa())
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
	require.Nil(t, err)

	sessionData, err := GetSessionFromFile(sessionFile)
	require.Nil(t, err)

	require.NotEqual(t, nil, sessionData.SessionInfo)
	require.NotEqual(t, "", sessionData.SessionInfo.SessionId)

	require.NotEqual(t, nil, sessionData.Env)
	require.NotEqual(t, "", sessionData.Env.Spec.SignerApiRoot)

	require.NotEqual(t, "", sessionData.Token)
}
