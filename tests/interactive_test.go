package test

// These tests are interactive and should be skipped in test
// suite. They require the user to fetch responses from email
// and input them.
//
// Running these tests with `go test` will not work as
// `go test` disables StdIn. Compiling the tests first
// to a binary and then running it works fine. i.e.,
// `go test -c ./... -v` compiles the test package.
// `./<testBinaryPrefix>.test -test.run <testName>
// runs the test.

import (
	"fmt"
	"testing"

	. "github.com/cubist-labs/cubesigner-go-sdk/client"
	"github.com/cubist-labs/cubesigner-go-sdk/models"
	. "github.com/cubist-labs/cubesigner-go-sdk/session"
	"github.com/cubist-labs/cubesigner-go-sdk/utils/ref"
	"github.com/stretchr/testify/require"
)

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

// Additionally follow http://docs.cubist.dev/end-user-wallets/providers/password
// to configure emails for alien_invite first.
func TestPasswordAuth(t *testing.T) {
	testOrg := testEnv.jsonSessionManager.Metadata().OrgID
	testPassword := "MytestpasswordBoomBamPow23$"
	env := EnvInterface{Spec: &Spec{
		SignerApiRoot: testEnv.jsonClient.RootUrl,
	}}
	// await user input for token
	fmt.Println("Enter test email:")
	var email string
	_, err := fmt.Scan(&email)
	require.Nil(t, err)

	// send invite
	_, err = testEnv.jsonClient.Invite(models.InviteRequest{
		Email: email,
		Name:  "User Name",
		Role:  ref.Of(models.Alien),
	})
	require.Nil(t, err)

	// await user input for token
	fmt.Println("Enter token received in email:")
	var token string
	_, err = fmt.Scan(&token)
	require.Nil(t, err)

	// accept invite
	_, err = InvitationAccept(env, testOrg, models.InvitationAcceptRequest{
		Token: token,
		Auth: models.AuthSource{
			Kind:       "password",
			Credential: testPassword,
		},
	})
	require.Nil(t, err)

	// get this user id
	users, err := testEnv.jsonClient.ListUsersInOrg(nil)
	require.Nil(t, err)
	var userId string
	for _, user := range users.Users {
		if *user.Email == email {
			userId = user.Id
			break
		}
	}
	require.NotEmpty(t, userId)
	defer deleteTestUser(t, testEnv.jsonClient, userId)

	// login
	_, err = IdpAuthenticate(
		env,
		testOrg,
		models.AuthenticationRequest{
			Email:    email,
			Password: testPassword,
		},
	)
	require.Nil(t, err)

	// try password reset
	resetResponse, err := IdpPasswordResetRequest(
		env,
		testOrg,
		models.PasswordResetRequest{
			Email: email,
		},
	)
	require.Nil(t, err)

	// Get the signature from user
	fmt.Println("Enter signature received in email:")
	var signature string
	_, err = fmt.Scan(&signature)
	require.Nil(t, err)
	// Get new password from user
	newPassword := "NewPasswordBoomBamPow23$"
	// Concatenate to create token
	token = resetResponse.PartialToken + signature

	_, err = IdpPasswordResetConfirm(
		env,
		testOrg,
		models.PasswordResetConfirmRequest{
			NewPassword: newPassword,
			Token:       token,
		},
	)
	require.Nil(t, err)

	// finally confirm new Login works
	_, err = IdpAuthenticate(
		env,
		testOrg,
		models.AuthenticationRequest{
			Email:    email,
			Password: newPassword,
		},
	)
	require.Nil(t, err)
}

// Additionally follow http://docs.cubist.dev/end-user-wallets/providers/email-otp
func TestEmailOtp(t *testing.T) {
	testOrg := testEnv.jsonSessionManager.Metadata().OrgID
	env := EnvInterface{Spec: &Spec{
		SignerApiRoot: testEnv.jsonClient.RootUrl,
	}}
	// await user input for token
	fmt.Println("Enter test email:")
	var email string
	_, err := fmt.Scan(&email)
	require.Nil(t, err)

	emailOtpResponse, err := EmailOtpAuth(
		env,
		testOrg,
		models.EmailOtpRequest{
			Email: email,
		},
	)
	require.Nil(t, err)

	// await user input for token
	fmt.Println("Enter signature sent in email:")
	var signature string
	_, err = fmt.Scan(&signature)
	require.Nil(t, err)

	// Construct the OIDC token
	idToken := emailOtpResponse.PartialToken + signature

	// use to register
	// create an Oidc proof
	proof, err := CreateProofOidc(env, testOrg, idToken)
	require.Nil(t, err)

	// create a user using proof
	userCreateResp, err := testEnv.jsonClient.CreateOidcUser(models.AddThirdPartyUserRequest{
		Proof: proof,
		Role:  models.Alien,
	})
	require.Nil(t, err)
	require.NotEmpty(t, userCreateResp.UserId)

	// clean-up delete the user
	_, err = testEnv.jsonClient.DeleteOidcUser(models.OidcIdentity{
		Iss: proof.Identity.Iss,
		Sub: proof.Identity.Sub,
	})
	require.Nil(t, err)
}
