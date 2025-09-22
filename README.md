# CubeSigner Go SDK

CubeSigner is a hardware-backed, non-custodial platform for securely managing cryptographic keys. This repository
is the Go SDK for programmatically interacting with CubeSigner services.

## CubeSigner background

[The Cubist team](https://cubist.dev/about) built CubeSigner to address the key
security vs key availability tradeoff: right now, many teams are forced to keep
keys available in memory and therefore exposed to attackers, or try to keep
keys safe—usually only at rest—at serious latency and engineering cost.
CubeSigner addresses this problem by giving developers low-latency access to
hardware-backed key generation and signing. During each of these operations,
CubeSigner safeguards their users' keys in HSM-sealed Nitro Enclaves—combining
cold wallet security with hot wallet speed and simplicity.

Right now, the CubeSigner SDK supports signing for EVM chains like Ethereum
and Avalanche, and non-EVM chains Bitcoin and Solana. Support for more chains
is in the works!

## Installing the SDK

Add the CubeSigner Go SDK to your project with:
```bash
go get github.com/cubist-labs/cubesigner-go-sdk
```

## Logging into CubeSigner

Before running the "getting started" examples below (or tests later), you must
log into your CubeSigner organization using the `cs` command-line tool, e.g.,

```bash
cs login owner@example.com --env '<gamma|prod|...>'
```

## Getting Started

In this section we are going to walk through a simple CubeSigner
setup. We'll create a signing key, then sign some EVM
transactions, and then add a security policy to restrict the kinds of
transactions that CubeSigner is allowed to sign.

To start, we'll instantiate the top-level `ApiClient` object from an
existing CubeSigner management session already stored on disk
(remember, you must already be logged in).

Let's also assume that the following imports are available to all the
examples below.

```go
import (
    "fmt"
    "log"
    "os"
    "strings"
    "time"

    "github.com/pquerna/otp/totp"
    "github.com/cubist-labs/cubesigner-go-sdk/session"
    "github.com/cubist-labs/cubesigner-go-sdk/client"
    "github.com/cubist-labs/cubesigner-go-sdk/models"
    "github.com/cubist-labs/cubesigner-go-sdk/spec/env"
    "github.com/cubist-labs/cubesigner-go-sdk/utils/ref"
)
```

We also use the following utilities to help us handle errors:

```go
func assert(cond bool, v ...any) {
	if !cond {
		log.Panic(v...)
	}
}

func assertError(err error, errorMsg string) {
	assert(err != nil, "Error expected, got nil")
	assert(
		strings.Contains(err.Error(), errorMsg),
		"Expected the error message to contain ", errorMsg, " but it doesn't: ", err.Error())
}

func assertNil(err error) {
	assert(err == nil, "Expected nil, got: ", err)
}
```

### Instantiate the Session Manager

Next, we need to instantiate the `SessionManager`, which
manages the [session auth and refresh tokens](https://signer-docs.cubist.dev/sessions/lifetimes-and-scopes)
behind the scenes.

We can do this by, for example, loading a session token from the
default location on disk (which is where the `cs login` command saves it):

```go
manager, err := session.NewJsonSessionManager(nil)
assertNil(err)
```

### Use the Client

Finally, we can create the API client to make a request:

```go
apiClient, err := client.NewApiClient(manager)
assertNil(err)
```

### Get `User` and `Org` info

We can now obtain some information about the logged-in user
and the organization the user belongs to:

```go
// Get user info
userInfo, err := apiClient.AboutMe()
assertNil(err)

// each user has a globally unique ID
userId := userInfo.UserId
fmt.Println(userId)

// Ids of all organizations this user is a member of
allOrgs := userInfo.Orgs
fmt.Println(allOrgs)

// Get org information
orgInfo, err := apiClient.GetOrg()
assert(err == nil && orgInfo.Enabled)
```

There is a lot more to do with an organization, like creating/listing
keys, creating/listing roles, setting up org-wide security policies,
etc.

For the rest of this tutorial, we assume the logged-in user is a member
of at least one organization.

### Create a `Key`

Next, let's create a key that we'll later use to sign an Ethereum
transaction. For that, we need a key of type `SecpEthAddr`.

```go
createKeyRequest := models.CreateKeyRequest{KeyType: models.SecpEthAddr, Count: 1}
keysInfo, err := apiClient.CreateKey(createKeyRequest)
assertNil(err)

// read response to get the key info
secpKey := keysInfo.Keys[0]
```

### Sign an Ethereum transaction

Lets create a dummy `Eth1SignRequest`.

```go
TxBody := models.TypedTransaction{}
TxBody.FromTypedTransactionEip1559(models.TypedTransactionEip1559{
    To: ref.Of("0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b"),
    Type: "0x02",
    Gas: ref.Of("0x61a80"),
    MaxFeePerGas: ref.Of("0x2540be400"),
    MaxPriorityFeePerGas: ref.Of("0x3b9aca00"),
    Nonce: ref.Of("0"),
    Value: ref.Of("0x100"),
})

eth1Request := models.Eth1SignRequest{
    ChainId: int64(1),
    Tx: TxBody,
}
```

It seems we have everything in place to sign this request with the
previously created key. However, attempting to do so fails with `403
Forbidden` saying something like `Session does not have the required scopes...`

```go
_, err = apiClient.EvmSign(secpKey.MaterialId, eth1Request)
// should fail with "Session does not have required scopes"
assertError(err, "Session does not have required scopes")
```

By default, the sessions created by the CLI cannot perform signing operations.
All sessions have a series of _scopes_ which determine what that session can be
used for. We'll talk more about this later, but for now just know that we need
a new session with the proper scopes:

```go
sessionResp, err := apiClient.CreateSession("Go sdk readme signing demo", []models.Scope{"manage:key:get", "sign:*"}, nil)
assertNil(err)

signingClient, err := client.NewApiClient(session.NewMemorySessionManager(sessionResp.ResponseData))
assertNil(err)

// retry signing
eth1Resp, err := signingClient.EvmSign(secpKey.MaterialId, eth1Request)
assertNil(err)

fmt.Println(eth1Resp.ResponseData)
```

### Access control with `Role`

CubeSigner uses roles to control access to keys when more than one user wants to
use them. You can think of roles as groups
that give certain users access to certain keys. To get started, let's
create a `Role` and then simply call `CreateSession` on it:

```go
roleResp, err := apiClient.CreateRole(&models.CreateRoleRequest{Name: "ReadmeRole"})
assertNil(err)

// Add key to the role
addKeyResp, err := apiClient.AddKeysToRole(roleResp.RoleId, models.AddKeysToRoleRequest{KeyIds: []string{secpKey.KeyId}})
assert(err == nil && addKeyResp.ResponseData != nil)

// Create a role session.
// Members of the role can create sessions which can only access keys in the role
roleSessionResp, err := apiClient.CreateRoleSession(roleResp.RoleId, models.CreateTokenRequest{
    Purpose: "Role session for Go SDK readme",
    // Role sessions implicitly have the "sign:*" scope
})
assertNil(err)

roleClient, err := client.NewApiClient(session.NewMemorySessionManager(roleSessionResp))
assertNil(err)

fmt.Printf("Created client for role %s\n", roleResp.RoleId)
```

### Set security policies

When we add a `Secp256k1` EVM key (i.e., key with type `models.SecpEthAddr`) to a role (as we did above), a client
associated with that role allows us to sign **any** EVM transaction with that key.
If that seems too permissive, we can attach a security policy to restrict the allowed usages of this key in
this role.

For example, to restrict signing to transactions with a pre-approved
recipient, we can attach a `TxReceiver` policy to our key:

```go
updateKeyRequest := models.UpdateKeyRequest{
    Policy: ref.Of([]interface{}{map[string]string{
        "TxReceiver": "0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b",
    }}),
}
updateKeyInfoResp, err := apiClient.UpdateKey(secpKey.KeyId, updateKeyRequest)
assertNil(err)

secpKey = *updateKeyInfoResp.ResponseData

// sign evm transaction with role session
eth1Resp, err = roleClient.EvmSign(secpKey.MaterialId, eth1Request)
assert(err == nil && eth1Resp.ResponseData.RlpSignedTx != "")
```

Try changing the transaction receiver and verify that the transaction
indeed gets rejected:

```go
fmt.Println("Signing a transaction to a different receiver must be rejected")

TxBody = models.TypedTransaction{}
TxBody.FromTypedTransactionEip1559(models.TypedTransactionEip1559{
    To: ref.Of("0x0000000000000000000000000000000000000000"),
    Type: "0x02",
    Gas: ref.Of("0x61a80"),
    MaxFeePerGas: ref.Of("0x2540be400"),
    MaxPriorityFeePerGas: ref.Of("0x3b9aca00"),
    Nonce: ref.Of("0"),
    Value: ref.Of("0x100"),
})

newEth1Request := models.Eth1SignRequest{
    ChainId: int64(1),
    Tx: TxBody,
}

_, err = roleClient.EvmSign(secpKey.MaterialId, newEth1Request)
assertError(err, "Transaction receiver not allowed by policy")
```

> **Warning**
> Setting new policies overwrites the previous ones.

### Sign a raw blob

The `ApiClient` class exposes the `BlobSign` method, which signs
an arbitrary (raw, uninterpreted) bag of bytes with a given key. This
operation, however, is not permitted by default; it is permanently
disabled for `BLS` keys, and for other key types it can be enabled by
attaching an `"AllowRawBlobSigning"` policy:

```go
// Create a Ed25519 key (e.g, for Cardano) and add it to our roleClient's role
createKeyRequest = models.CreateKeyRequest{KeyType: models.Ed25519CardanoAddrVk, Count: 1}
createKeyResp, err := apiClient.CreateKey(createKeyRequest)
assertNil(err)

// add to role
edKey := createKeyResp.Keys[0]
addKeysResp, err := apiClient.AddKeysToRole(roleResp.RoleId, models.AddKeysToRoleRequest{KeyIds: []string{edKey.KeyId}})
assert(err == nil && !addKeysResp.RequiresMfa())

// Sign raw blobs with our new ed key and the secp key we created before
for _, thisKey := range []models.KeyInfo{secpKey, edKey} {
    fmt.Printf("Confirming that raw blob with %s is rejected\n", thisKey.KeyType)
    blobSignRequest := models.BlobSignRequest {
        MessageBase64: "L1kE9g59xD3fzYQQSR7340BwU9fGrP6EMfIFcyX/YBc=",
    }

    _, err = roleClient.BlobSign(thisKey.KeyId, blobSignRequest)
    assertError(err, "Raw blob signing not allowed")

    // add Raw blob signing policy
    newPolicy := append(thisKey.Policy, "AllowRawBlobSigning")
    updateKeyRequest := models.UpdateKeyRequest{
        Policy: &newPolicy,
    }
    _, err := apiClient.UpdateKey(thisKey.KeyId, updateKeyRequest)
    assertNil(err)

    // try signing again
    sigResp, err := roleClient.BlobSign(thisKey.KeyId, blobSignRequest)
    assert(err == nil && sigResp.ResponseData.Signature != "")
}
```

> **Warning**
> When signing a raw blob with a `Secp256k1` key, the blob **MUST** be the output of a secure hash function like SHA-256, and must be exactly 32 bytes long. This is a strict requirement of the ECDSA signature algorithm used by Bitcoin, Ethereum, and other blockchains. Signing any byte string that is not the output of a secure hash function can lead to catastrophic security failure, including completely leaking your secret key.

Trying to sign an invalid message with a secp key will fail with
`400 Bad Request` saying `Signature scheme: InvalidMessage`.

### Session Management

In the above examples we've used 3 different sessions:

1. A management session that we created using the CLI
2. A signing session that we created using (1)
3. A role session that we created used (1)

All `ApiClient`s require a valid session in order to operate. In this section
we'll dive into the specifics of sessions in the Go SDK.

### Loading from disk

If you already have an active session in `cs` (the CubeSigner CLI), you can
load it into the Go SDK with a simple helper (as we did earlier).

```go
jsonManager, err := session.NewJsonSessionManager(nil)
assertNil(err)
```

Or we can use the CLI to create our own session explicitly for our Go client:

```bash
cs session create --role-id $ROLE_ID --scope sign-all --output json > session.json
```

Then we can load it by replacing `nil` with `ref.Of("./session.json")` like so:

```go norun
jsonManager, err := session.NewJsonSessionManager(ref.Of("./session.json"))
assertNil(err)
```

```go
// create a client to use this session manager
jsonSessionClient, err := client.NewApiClient(jsonManager)
assertNil(err)

fmt.Printf("Created client with session: %s\n", jsonSessionClient.Manager.Metadata())
```

### Loading from Memory

If you already have the session information (`SessionData` in Go) in memory, you can
load that directly into a client. We did so when creating a role session.

```go
roleSessionResp, err = apiClient.CreateRoleSession(roleResp.RoleId, models.CreateTokenRequest{
    Purpose: "Role session for Go SDK readme",
})
assertNil(err)

// create a in-memory session manager
memManager := session.NewMemorySessionManager(roleSessionResp)

// create a client to use this session manager
memSessionClient, err := client.NewApiClient(memManager)
assertNil(err)

fmt.Printf("Created client with session: %s\n", memSessionClient.Manager.Metadata())
```

### Loading from AWS Secrets Manager

Sessions stored in AWS Secrets Manager can be loaded with the `AwsSessionManager`. The `AwsSessionManager` 
does not auto-refresh the secret session and a separate rotation lambda is expected for this purpose.

```go norun
secretId := "AwsCSSession"
// if AwsSecretSessionManagerOpts are nil, the default aws configuration is loaded
awsSessionManager, err := session.NewAwsSessionManager(secretId, nil)
assertNil(err)
```

> [!WARNING]  
> Clients created this way will automatically refresh the session. If you try to use this session with another client, they will both try to refresh, leading to failures.

### Clients, Managers, and Refreshing

As we've seen in the examples above, all `client.ApiClient`s are constructed using the `client.NewApiClient` constructor. The
`client.NewApiClient` constructor accepts a `client.SessionManager`. So far we have seen three different session managers:

- `AwsSessionManager`
- `JsonSessionManager`
- `MemorySessionManager`

These managers are responsible for keeping your session tokens refreshed and (optionally) persisted. Whenever
your session tokens are refreshed, `JsonSessionManager` will write the new tokens to disk.

More complex managers can be written by implementing the `client.SessionManager` interface.

### Create a session for an OIDC user

CubeSigner supports the [OIDC](https://openid.net/developers/how-connect-works/)
standard for authenticating third-party users. This is typically done on the client-side
rather than server-side.

First, we need an OIDC token. We can get one from Google or any other supported OIDC issuer. For
the purpose of this example, we'll assume the OIDC token is stored in the `OIDC_TOKEN` environment
variable.

```go
oidcToken := os.Getenv("OIDC_TOKEN")
assert(oidcToken != "")
```

Before we can use the OIDC token for authentication, we must add an org policy
to allow the particular issuer/audience pair from the token.

```go norun
getOrgResp, err := apiClient.GetOrg()
assertNil(err)

if getOrgResp.Policy != nil {
    oldPolicy := getOrgResp.Policy
    fmt.Println(oldPolicy)
}

// parse OIDC token to get issuer and audience 
oidcSplits := strings.Split(oidcToken, ".")
decoded, err := base64.RawURLEncoding.DecodeString(oidcSplits[1])
assertNil(err)

var oidcPayload map[string]interface{}
err = json.Unmarshal(decoded, &oidcPayload)
assertNil(err)

// map issuer to audience for policy body
issMap := map[string][]string{oidcPayload["iss"].(string): {oidcPayload["aud"].(string)}}

// OidcAuthSources policy body
oidcAuthSourcesPolicy := map[string]interface{}{
    "OidcAuthSources": issMap,
}

// update org policy
updateOrgRequest := models.UpdateOrgRequest{
    Policy: ref.Of([]map[string]interface{}{oidcAuthSourcesPolicy}),
}
_, err = apiClient.UpdateOrg(updateOrgRequest)
assertNil(err)
```

Finally, exchange the OIDC token for a session.

```go
env := env.Gamma
orgId := "Org#..."
oidcLoginRequest := models.OidcLoginRequest {
    Scopes: []models.Scope{"manage:mfa:*", "sign:*"},
}
oidcSessionResp, err := client.OidcAuth(env, orgId, oidcToken, oidcLoginRequest)
assertNil(err)

oidcClient, err := client.NewApiClient(session.NewMemorySessionManager(oidcSessionResp.ResponseData))
assertNil(err)
```

### Set up TOTP for a user

To manage a user we need a session bound to that user. It
doesn't matter if that user is native to CubeSigner or a third-party
OIDC user. For that purpose, in this section we are going to use the
previously created `oidcClient` instance.

To set up TOTP, we first call the `UserResetTotpInit` method to initiate a
TOTP reset procedure on the client-side.

```go
fmt.Printf("Setting up TOTP for user %s\n", *userInfo.Email)
totpResetResp, err := oidcClient.UserResetTotpInit(nil)
assertNil(err)
```

If the user has already configured TOTP (or any other form of MFA),
this response will require multi factor authentication. In that case,
for example, call `totpApprove` and provide the code for the existing
TOTP to proceed:

```go
totpSecret := os.Getenv("CS_USER_TOTP_SECRET")

if totpResetResp.RequiresMfa() {
    fmt.Println("Resetting TOTP requires MFA")
    totpCode, err := totp.GenerateCode(totpSecret, time.Now())
    assertNil(err)

    // approve mfa with totp
    mfaVoteTotpParams := models.MfaVoteTotpParams{
        MfaVote: ref.Of(models.Approve),
    }
    totpApproveRequest := models.TotpApproveRequest{
        Code: totpCode,
    }
    mfaTotpResp, err := oidcClient.MfaVoteTotp(totpResetResp.MfaRequired.Id, &mfaVoteTotpParams, totpApproveRequest)
    assertNil(err)

    // resubmit with MfaReceipt
    totpResetResp, err = oidcClient.UserResetTotpInit(nil, client.GetReceipt(mfaTotpResp))
    assert(err == nil && !totpResetResp.RequiresMfa())
}
```

The response contains a TOTP challenge, i.e., a new TOTP
configuration in the form of the standard
[TOTP url](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).
From that url, we can generate a QR code to present to the user, or
create an authenticator for automated testing.

```go
totpChallengeId := totpResetResp.ResponseData.TotpId
totpChallengeUrl := totpResetResp.ResponseData.TotpUrl
assert(totpChallengeUrl != "" && totpChallengeId != "")
```

To complete the challenge, we must call `UserResetTotpComplete` and
provide the TOTP code matching the TOTP configuration from the challenge:

```go norun
parsedUrl, _ := url.Parse(totpChallengeUrl)
urlParams, _ := url.ParseQuery(parsedUrl.RawQuery)
totpSecret = urlParams["secret"][0]

newTotpCode, err := totp.GenerateCode(totpSecret, time.Now())
assertNil(err)

totpChallengeAnswer := models.TotpChallengeAnswer {
    Code: newTotpCode,
    TotpId: totpChallengeId,
}
_, err = oidcClient.UserResetTotpComplete(totpChallengeAnswer)
assertNil(err)
```

After TOTP is configured, we can double check that our authenticator
is generating the correct code by calling `UserVerifyTotp`

```go
fmt.Println("Verifying current TOTP code")
totpCode, err := totp.GenerateCode(totpSecret, time.Now())
assertNil(err)

_, err = oidcClient.UserVerifyTotp(models.TotpApproveRequest{Code: totpCode})
assertNil(err)
```

We can also check that the user's profile now indeed includes `Totp`
as one of the configured MFA factors.

```go
userInfo, err = oidcClient.AboutMe()
assertNil(err)

foundTotp := false
for _, configuredMfa := range userInfo.Mfa {
    totpMfa, err := configuredMfa.AsConfiguredMfaTotp()
    assertNil(err)
    if totpMfa.Type == "totp" {
        foundTotp = true
    }
}

assert(foundTotp)
```

### Configure MFA policy for signing

We've already discussed assigning a [security
policy](#set-security-policies) to a key; requiring multi-factor
authentication is another such policy.

Let's update our `secpKey` key to require an additional approval via
TOTP before anything may be signed with that key:

```go
fmt.Printf("Require Totp for key %s\n", secpKey.MaterialId)

// append current policy to require Mfa
newPolicy := append(secpKey.Policy, client.RequireMfaPolicy{RequireMfa: &models.MfaPolicy{
    Count: ref.Of(int32(1)),
    AllowedMfaTypes: ref.Of([]models.MfaType{client.TotpMfaType()}),
}})

_, err = apiClient.UpdateKey(secpKey.KeyId, models.UpdateKeyRequest{Policy: &newPolicy})
assertNil(err)
```

Now, when we call any signing operation on `secpKey`, we'll
receive `202 Accepted` instead of `200 Ok`. The response body contains
an MFA ID, which we can use to fetch and inspect the associated MFA
request, see how many approvals it requires, what kind of MFA factors
it allows, etc. Instead, since we know that our key requires TOTP, we
can just call `MfaVoteTotp` on the response and pass the current TOTP
code to it; if the code is correct, the call will succeed
and return updated `MfaRequestInfo`. We then call `client.GetReceipt`
to check if the approval was successful. With the `MfaReceipt` we can
resubmit the original request to get the signature.

```go
fmt.Println("Signing a transaction now requires TOTP")

eth1Resp, err = oidcClient.EvmSign(secpKey.MaterialId, eth1Request)
assert(err == nil && eth1Resp.RequiresMfa())

// approve request
totpCode, err = totp.GenerateCode(totpSecret, time.Now())
assertNil(err)

params := models.MfaVoteTotpParams{
    MfaVote: ref.Of(models.Approve),
}
approveRequest := models.TotpApproveRequest{
    Code: totpCode,
}
mfaTotpResp, err := oidcClient.MfaVoteTotp(eth1Resp.MfaRequired.Id, &params, approveRequest)
assert(err == nil && client.GetReceipt(mfaTotpResp) != nil)

// resubmit with receipt
eth1Resp, err = oidcClient.EvmSign(secpKey.MaterialId, eth1Request, client.GetReceipt(mfaTotpResp))
assert(err == nil && !eth1Resp.RequiresMfa() && eth1Resp.ResponseData.RlpSignedTx != "")
```

### Clean up

Once we are done, we can revoke the sessions and delete the keys
we created. 

```go
fmt.Println("Cleaning up")

// clean up signing session
_, err = signingClient.RevokeCurrentSession()
assertNil(err)

// clean up role session
_, err = roleClient.RevokeCurrentSession()
assertNil(err)

// clean up oidc session
_, err = oidcClient.RevokeCurrentSession()
assertNil(err)

// clean up role
_, err = apiClient.DeleteRole(roleResp.RoleId)
assertNil(err)

// Delete keys
deleteResp, err := apiClient.DeleteKey(secpKey.KeyId)
assertNil(err)

if deleteResp.RequiresMfa() {
    totpCode, err = totp.GenerateCode(totpSecret, time.Now())
    assertNil(err)

    params := models.MfaVoteTotpParams{MfaVote: ref.Of(models.Approve)}
    totpApproveRequest := models.TotpApproveRequest{Code: totpCode}
    mfaTotpResp, err = apiClient.MfaVoteTotp(deleteResp.MfaRequired.Id, &params, totpApproveRequest)
    assert(err == nil && client.GetReceipt(mfaTotpResp) != nil)

    // resubmit
    deleteResp, err := apiClient.DeleteKey(secpKey.KeyId, client.GetReceipt(mfaTotpResp))
    assert(err == nil && !deleteResp.RequiresMfa())

}

// Delete EdKey
_, err = apiClient.DeleteKey(edKey.KeyId)
assertNil(err)
```

### Running the SDK tests

After [logging in](#logging-into-cubesigner) and setting the `OIDC_TOKEN` environment variable, you can just run:

```bash
make tests
```

Tests in `tests/interactive_test.go` are interactive test and must be compiled and
run separately:

```bash
go test -c ./... -v # compiles all tests.
./test.test -test.run TestMfaSignEmail # runs TestMfaSignEmail
```

User input, e.g., Email Otp is needed for these tests and must be provided by the user in the
CLI.
