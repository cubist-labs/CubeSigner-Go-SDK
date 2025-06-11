// This file provides various API endpoint methods on ApiClient.
//
// Code is auto-generated for cubesigner_go_sdk. DO NOT EDIT.

package client

import (
	"fmt"

	"github.com/cubist-labs/cubesigner-go-sdk/models"
	"github.com/cubist-labs/cubesigner-go-sdk/session"
)

// List accessible organizations.
//
// Unauthenticated endpoint for retrieving all organizations accessible to a user.
// This information is emailed to the provided email address.
func EmailMyOrgs(env session.EnvInterface, queryParameters models.EmailMyOrgsParams) (*models.EmptyImpl, error) {
	queryParams := make(map[string]string)
	queryParams["email"] = queryParameters.Email
	client, err := NewApiClient(&noSessionManager{RootUrl: env.Spec.SignerApiRoot})
	if err != nil {
		return nil, err
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "GET",
		path:        "/v0/email/orgs",
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Get Org
//
// Retrieves information about an organization.
func (client *ApiClient) GetOrg() (*models.OrgInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "GET",
		path:   "/v0/org/{org_id}",
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.OrgInfo](resp)
}

// Update Org
//
// Update organization attributes (enabled flag, name, and policies).
func (client *ApiClient) UpdateOrg(updateOrgRequest models.UpdateOrgRequest) (*models.UpdateOrgResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "PATCH",
		path:   "/v0/org/{org_id}",
		body:   updateOrgRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.UpdateOrgResponse](resp)
}

// Associate an OIDC identity with an arbitrary user in org <session.org>.
func (client *ApiClient) AuthMigrationIdentityAdd(migrateIdentityRequest models.MigrateIdentityRequest) (*models.EmptyImpl, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/auth_migration/add_identity",
		body:   migrateIdentityRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Dissociate an OIDC identity from an arbitrary user in org <session.org>.
func (client *ApiClient) AuthMigrationIdentityRemove(migrateIdentityRequest models.MigrateIdentityRequest) (*models.EmptyImpl, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/auth_migration/remove_identity",
		body:   migrateIdentityRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Sign a serialized Avalanche C/X/P-Chain Message
//
// Signs an Avalanche message with a given SecpEth (C-Chain messages) or
// SecpAva (X- and P-Chain messages) key. Currently signing C-Chain messages
// with SecpEth key must also be explicitly allowed via `AllowRawBlobSigning`
// policy.
//
// This is a pre-release feature.
func (client *ApiClient) AvaSerializedTxSign(avaChain string, pubkey string, avaSerializedTxSignRequest models.AvaSerializedTxSignRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.SignResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/ava/sign/{ava_chain}/{pubkey}",
		pathParams:  map[string]string{"ava_chain": avaChain, "pubkey": pubkey},
		body:        avaSerializedTxSignRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.SignResponse](resp)
}

// Sign JSON-encoded Avalanche X- or P-Chain Message
//
// Signs an Avalanche message with a given SecpAva key.
// This is a pre-release feature.
func (client *ApiClient) AvaSign(pubkey string, avaSignRequest models.AvaSignRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.SignResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/ava/sign/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        avaSignRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.SignResponse](resp)
}

// Sign Babylon Covenant Committee Request
//
// Signs transactions relevant to a Babylon covenant committee signer,
// i.e., Schnorr and adaptor signatures for the unbonding, slashing, and
// slash-unbonding outputs of a Babylon staking transaction.
func (client *ApiClient) BabylonCovSign(pubkey string, babylonCovSignRequest models.BabylonCovSignRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.BabylonCovSignResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/babylon/cov/sign/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        babylonCovSignRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.BabylonCovSignResponse](resp)
}

// Create EOTS nonces
//
// Generates a set of Babylon EOTS nonces for a specified chain-id, starting at a
// specified block height.
func (client *ApiClient) CreateEotsNonces(pubkey string, eotsCreateNonceRequest models.EotsCreateNonceRequest) (*models.EotsCreateNonceResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "POST",
		path:       "/v0/org/{org_id}/babylon/eots/nonces/{pubkey}",
		pathParams: map[string]string{"pubkey": pubkey},
		body:       eotsCreateNonceRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EotsCreateNonceResponse](resp)
}

// Create an EOTS signature
//
// Generates an EOTS signature for the specified chain-id, block height, and message.
func (client *ApiClient) EotsSign(pubkey string, eotsSignRequest models.EotsSignRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.SignResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/babylon/eots/sign/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        eotsSignRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.SignResponse](resp)
}

// Sign Babylon Staking Registration
//
// Creates and signs the data needed to register a Phase-2 or Phase-3
// Babylon stake. This includes the deposit and unbonding transactions,
// two slashing transactions, the slashing signatures, and the proof of
// possession.
//
// Note that it is also possible to generate this registration data by
// making four calls to the Babylon staking API, plus one call to the
// PSBT signing API to generate the BIP-322 proof of possession. The
// registration API generates the same data but is easier to use.
//
// Note that this action can only be called with a Taproot key. If your
// deposit transaction spends UTXOs that are controlled by other keys,
// you can submit the 'deposit' PSBT to the PSBT signing API one or more
// times to generate the required signatures.
//
// For more information, consult the
// [Babylon documentation](https://github.com/babylonlabs-io/babylon/blob/release/v1.x/docs/register-bitcoin-stake.md).
//
// This is a pre-release feature.
func (client *ApiClient) BabylonRegistration(pubkey string, babylonRegistrationRequest models.BabylonRegistrationRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.BabylonRegistrationResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/babylon/registration/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        babylonRegistrationRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.BabylonRegistrationResponse](resp)
}

// Sign Babylon Staking Transaction
//
// Creates and signs transactions related to Babylon staking (i.e.,
// deposit, early unbond, withdrawal). The return value is a Pre-Signed
// Bitcoin Transaction (PSBT), as defined in BIP-174, which matches the
// format used in most Babylon tooling.
//
// The 'deposit' action can be used with either Segwit (i.e., SecpBtc/SecpBtcTest)
// or Taproot (i.e., TaprootBtc/TaprootBtcTest) keys. The remaining actions can be
// used only with Taproot keys.
//
// This is a pre-release feature.
func (client *ApiClient) BabylonStaking(pubkey string, babylonStakingRequest models.BabylonStakingRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.BabylonStakingResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/babylon/staking/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        babylonStakingRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.BabylonStakingResponse](resp)
}

// Sign a Bitcoin message.
//
// Signs a message using BIP137 message signing with a given Secp256k1 key.
func (client *ApiClient) BtcMessageSign(pubkey string, btcMessageSignRequest models.BtcMessageSignRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.BtcMessageSignResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/btc/message/sign/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        btcMessageSignRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.BtcMessageSignResponse](resp)
}

// Sign a Partially Signed Bitcoin Transaction (PSBT)
//
// Signs all inputs of the supplied PSBT v0 (BIP-174) that pertain to the
// 'pubkey' specified in the request, which can be either a Taproot or a
// Segwit key. For Segwit keys, CubeSigner-specific deterministic tweaking
// can be applied to 'pubkey' before signing, on a per-input basis. (See the
// CubeSigner documentation for more information on Segwit tweaking.)
//
// When calling with a segwit key the required scope is 'sign:btc:psbt:segwit'.
// For a taproot key, the scope is 'sign:btc:psbt:taproot'. Either type of key
// can be used with the 'sign:btc:psbt' scope.
//
// This is a pre-release feature.
func (client *ApiClient) PsbtSign(pubkey string, psbtSignRequest models.PsbtSignRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.PsbtSignResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/btc/psbt/sign/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        psbtSignRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.PsbtSignResponse](resp)
}

// Sign Bitcoin Segwit Transaction
//
// Signs a Bitcoin Segwit transaction with a given key.
// This is a pre-release feature.
func (client *ApiClient) BtcSign(pubkey string, btcSignRequest models.BtcSignRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.SignResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/btc/sign/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        btcSignRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.SignResponse](resp)
}

// Sign Bitcoin Taproot Transaction
//
// Signs a Bitcoin Taproot transaction with a given key.
// This is a pre-release feature.
func (client *ApiClient) BtcTaprootSign(pubkey string, taprootSignRequest models.TaprootSignRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.SignResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/btc/taproot/sign/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        taprootSignRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.SignResponse](resp)
}

// List Contacts
//
// List all contacts in the org.
// Any org member is allowed to list all contacts in the org.
func (client *ApiClient) ListContacts(queryParameters *models.ListContactsParams) (*models.PaginatedListContactsResponse, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.PageSize != nil {
			pageSizeStr := fmt.Sprintf("%v", *queryParameters.PageSize)
			queryParams["page.size"] = pageSizeStr
		}
		if queryParameters.PageStart != nil {
			queryParams["page.start"] = *queryParameters.PageStart
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "GET",
		path:        "/v0/org/{org_id}/contacts",
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PaginatedListContactsResponse](resp)
}

// Create Contact
//
// Creates a new contact in the organization-wide address book. The
// user making the request is the owner of the contact, giving them edit access
// to the contact along with the org owners.
func (client *ApiClient) CreateContact(createContactRequest models.CreateContactRequest) (*models.ContactInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/contacts",
		body:   createContactRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.ContactInfo](resp)
}

// Get Contact
//
// Returns the properties of a Contact.
func (client *ApiClient) GetContact(contactId string) (*models.ContactInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "GET",
		path:       "/v0/org/{org_id}/contacts/{contact_id}",
		pathParams: map[string]string{"contact_id": contactId},
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.ContactInfo](resp)
}

// Delete Contact
//
// Delete a contact, specified by its ID.
//
// Only the contact owner and org owners are allowed to delete contacts.
// Additionally, the contact's edit policy (if set) must permit the deletion.
func (client *ApiClient) DeleteContact(contactId string) (*models.EmptyImpl, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "DELETE",
		path:       "/v0/org/{org_id}/contacts/{contact_id}",
		pathParams: map[string]string{"contact_id": contactId},
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Update Contact
//
// Updates an existing contact in the organization-wide address book. Only
// the contact owner or an org owner can update contacts.
//
// *Updates will overwrite the existing value of the field.*
func (client *ApiClient) UpdateContact(contactId string, updateContactRequest models.UpdateContactRequest) (*models.ContactInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "PATCH",
		path:       "/v0/org/{org_id}/contacts/{contact_id}",
		pathParams: map[string]string{"contact_id": contactId},
		body:       updateContactRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.ContactInfo](resp)
}

// Get current counts of users and keys within an org.
func (client *ApiClient) Counts() (*models.ComputeCountsResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "GET",
		path:   "/v0/org/{org_id}/counts",
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.ComputeCountsResponse](resp)
}

// Derive Key From New Or Existing Long-Lived Mnemonic
//
// Uses either a new or existing long-lived mnemonic to derive keys of
// one or more specified types via specified derivation paths.
func (client *ApiClient) DeriveKey(deriveKeysRequest models.DeriveKeysRequest) (*models.CreateKeyResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "PUT",
		path:   "/v0/org/{org_id}/derive_keys",
		body:   deriveKeysRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.CreateKeyResponse](resp)
}

func (client *ApiClient) ConfigureEmail(purpose string, configureEmailRequest models.ConfigureEmailRequest) (*models.EmptyImpl, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "PUT",
		path:       "/v0/org/{org_id}/emails/{purpose}",
		pathParams: map[string]string{"purpose": purpose},
		body:       configureEmailRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Sign EIP-191 Data
//
// Signs a message using EIP-191 personal_sign with a given Secp256k1 key.
func (client *ApiClient) Eip191Sign(pubkey string, eip191SignRequest models.Eip191SignRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.SignResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/evm/eip191/sign/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        eip191SignRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.SignResponse](resp)
}

// Sign EIP-712 Typed Data
//
// Signs typed data according to EIP-712 with a given Secp256k1 key.
func (client *ApiClient) Eip712Sign(pubkey string, eip712SignRequest models.Eip712SignRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.SignResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/evm/eip712/sign/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        eip712SignRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.SignResponse](resp)
}

// Get an Org-Export Ciphertext
//
// Returns the export ciphertext associated with the provided key-id.
// In order to use this API, you must be an org owner and your org must
// be configured for org export and for API-based export delivery.
func (client *ApiClient) GetOrgExport(keyId string) (*models.OrgExportResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "GET",
		path:       "/v0/org/{org_id}/export/{key_id}",
		pathParams: map[string]string{"key_id": keyId},
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.OrgExportResponse](resp)
}

// List associated OIDC identities with the current user.
func (client *ApiClient) ListOidcIdentities() (*models.ListIdentitiesResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "GET",
		path:   "/v0/org/{org_id}/identity",
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.ListIdentitiesResponse](resp)
}

// Associate an OIDC identity with the current user in org <session.org>.
//
// Alien users are allowed to call this endpoint, but for them MFA is always required;
// additionally, limits may apply to how many identities that may register.
func (client *ApiClient) AddOidcIdentity(addIdentityRequest models.AddIdentityRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.EmptyImpl], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/identity",
		body:        addIdentityRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.EmptyImpl](resp)
}

// Remove an OIDC identity from the current user's account in org <session.org>.
func (client *ApiClient) RemoveOidcIdentity(oidcIdentity models.OidcIdentity) (*models.EmptyImpl, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "DELETE",
		path:   "/v0/org/{org_id}/identity",
		body:   oidcIdentity,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Create [IdentityProof] from CubeSigner user session
//
// This route can be used to prove to another party that a user has a
// valid CubeSigner session.
//
// Clients are intended to call this route and pass the returned evidence
// to another service which will verify it by making a request to `/v0/org/<org_id>/identity/verify`.
func (client *ApiClient) CreateProofCubeSigner() (*models.IdentityProof, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/identity/prove",
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.IdentityProof](resp)
}

// Create [IdentityProof] from OIDC token
//
// Exchange an OIDC ID token (passed via the `Authorization` header) for a proof of authentication.
//
// This route can be used to prove to another party that a user has met the
// authentication requirements (allowed issuers & audiences) for CubeSigner
// without leaking their credentials.
//
// Clients are intended to call this route and pass the returned evidence to another service
// which will verify it by making a request to `/v0/org/<org_id>/identity/verify`.
func CreateProofOidc(env session.EnvInterface, orgId string, idToken string) (*models.IdentityProof, error) {
	client, err := NewApiClient(&noSessionManager{OrgID: orgId, RootUrl: env.Spec.SignerApiRoot})
	if err != nil {
		return nil, err
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:  "POST",
		path:    "/v0/org/{org_id}/identity/prove/oidc",
		headers: map[string]string{"Authorization": idToken},
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.IdentityProof](resp)
}

// Verify identity proof
//
// Allows a third-party to validate proof of authentication.
//
// When a third-party is provided an [IdentityProof] object, they must check its
// veracity by calling this endpoint
func (client *ApiClient) VerifyProof(identityProof models.IdentityProof) (*GenericHttpResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/identity/verify",
		body:   identityProof,
	})
	return resp, err
}

// Authenticate
//
// This endpoint exchanges an email & password for an OIDC token
func IdpAuthenticate(env session.EnvInterface, orgId string, authenticationRequest models.AuthenticationRequest) (*models.AuthenticationResponse, error) {
	client, err := NewApiClient(&noSessionManager{OrgID: orgId, RootUrl: env.Spec.SignerApiRoot})
	if err != nil {
		return nil, err
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/idp/authenticate",
		body:   authenticationRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.AuthenticationResponse](resp)
}

// Request Password Reset
//
// This endpoint generates an OIDC token without a signature (of the form `{header}.{payload}.`),
// and sends the signature to the user's email. Client applications can reconstruct the token
// by concatenating the `{header}.{payload}.` with the signature, producing a valid OIDC token of
// the form `{header}.{payload}.{signature}`. The token can then be used to authenticate the user
// when performing the `idp_password_reset_confirm` request.
func IdpPasswordResetRequest(env session.EnvInterface, orgId string, passwordResetRequest models.PasswordResetRequest) (*models.EmailOtpResponse, error) {
	client, err := NewApiClient(&noSessionManager{OrgID: orgId, RootUrl: env.Spec.SignerApiRoot})
	if err != nil {
		return nil, err
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/idp/password_reset",
		body:   passwordResetRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmailOtpResponse](resp)
}

// Confirm Password Reset
//
// This endpoint allows IDP users to reset their password
// using a token they have received in their email.
func IdpPasswordResetConfirm(env session.EnvInterface, orgId string, passwordResetConfirmRequest models.PasswordResetConfirmRequest) (*models.EmptyImpl, error) {
	client, err := NewApiClient(&noSessionManager{OrgID: orgId, RootUrl: env.Spec.SignerApiRoot})
	if err != nil {
		return nil, err
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "PATCH",
		path:   "/v0/org/{org_id}/idp/password_reset",
		body:   passwordResetConfirmRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Create Key-Import Key
//
// Generate an ephemeral key that a client can use for key-import encryption.
func (client *ApiClient) CreateKeyImportKey() (*models.CreateKeyImportKeyResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "GET",
		path:   "/v0/org/{org_id}/import_key",
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.CreateKeyImportKeyResponse](resp)
}

// Import Key
//
// Securely imports an existing key using a previously generated key-import key.
func (client *ApiClient) ImportKey(importKeyRequest models.ImportKeyRequest) (*models.CreateKeyResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "PUT",
		path:   "/v0/org/{org_id}/import_key",
		body:   importKeyRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.CreateKeyResponse](resp)
}

// Public Org Info
//
// Unauthenticated endpoint that returns publicly-available information about an organization.
func PublicOrgInfo(env session.EnvInterface, orgId string) (*models.PublicOrgInfo, error) {
	client, err := NewApiClient(&noSessionManager{OrgID: orgId, RootUrl: env.Spec.SignerApiRoot})
	if err != nil {
		return nil, err
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "GET",
		path:   "/v0/org/{org_id}/info",
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PublicOrgInfo](resp)
}

// Accept an invitation
//
// This endpoint allows idp users to register using a token they have received in their email
func InvitationAccept(env session.EnvInterface, orgId string, invitationAcceptRequest models.InvitationAcceptRequest) (*GenericHttpResponse, error) {
	client, err := NewApiClient(&noSessionManager{OrgID: orgId, RootUrl: env.Spec.SignerApiRoot})
	if err != nil {
		return nil, err
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/invitation/accept",
		body:   invitationAcceptRequest,
	})
	return resp, err
}

// Invite User
//
// Creates a new user in an existing org and sends that user an invite email.
func (client *ApiClient) Invite(inviteRequest models.InviteRequest) (*models.EmptyImpl, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/invite",
		body:   inviteRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// List Keys
//
// Gets the list of accessible keys in a given org (to org owner, all org keys
// are accessible; to members, only their own keys are accessible).
//
// If a search condition is, the result will contain only the keys whose either
// material ID or metadata contain the search condition string.
//
// NOTE that if pagination is used and a page limit is set, the returned result
// set may contain either FEWER or MORE elements than the requested page limit.
func (client *ApiClient) ListKeysInOrg(queryParameters *models.ListKeysInOrgParams) (*models.PaginatedListKeysResponse, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.PageSize != nil {
			pageSizeStr := fmt.Sprintf("%v", *queryParameters.PageSize)
			queryParams["page.size"] = pageSizeStr
		}
		if queryParameters.PageStart != nil {
			queryParams["page.start"] = *queryParameters.PageStart
		}
		if queryParameters.KeyType != nil {
			keyTypeStr := fmt.Sprintf("%v", *queryParameters.KeyType)
			queryParams["key_type"] = keyTypeStr
		}
		if queryParameters.KeyOwner != nil {
			keyOwnerStr := fmt.Sprintf("%v", *queryParameters.KeyOwner)
			queryParams["key_owner"] = keyOwnerStr
		}
		if queryParameters.Search != nil {
			queryParams["search"] = *queryParameters.Search
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "GET",
		path:        "/v0/org/{org_id}/keys",
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PaginatedListKeysResponse](resp)
}

// Create Key
//
// Creates one or more new keys of the specified type.
func (client *ApiClient) CreateKey(createKeyRequest models.CreateKeyRequest) (*models.CreateKeyResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/keys",
		body:   createKeyRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.CreateKeyResponse](resp)
}

// Get Key
//
// Returns the properties of a key.
func (client *ApiClient) GetKeyInOrg(keyId string) (*models.KeyInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "GET",
		path:       "/v0/org/{org_id}/keys/{key_id}",
		pathParams: map[string]string{"key_id": keyId},
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.KeyInfo](resp)
}

// Delete Key
//
// Deletes a key specified by its ID.
//
// Only the key owner and org owners are allowed to delete keys.
// Additionally, the role's edit policy (if set) must permit the update.
func (client *ApiClient) DeleteKey(keyId string, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.EmptyImpl], error) {
	resp, err := client.send(&payload{
		method:      "DELETE",
		path:        "/v0/org/{org_id}/keys/{key_id}",
		pathParams:  map[string]string{"key_id": keyId},
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.EmptyImpl](resp)
}

// Update Key
//
// Enable or disable a key.  The user must be the owner of the key or
// organization to perform this action.
//
// For each requested update, the session must have the corresponding 'manage:key:update:_' scope;
// if no updates are requested, the session must have 'manage:key:get'.
func (client *ApiClient) UpdateKey(keyId string, updateKeyRequest models.UpdateKeyRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.KeyInfo], error) {
	resp, err := client.send(&payload{
		method:      "PATCH",
		path:        "/v0/org/{org_id}/keys/{key_id}",
		pathParams:  map[string]string{"key_id": keyId},
		body:        updateKeyRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.KeyInfo](resp)
}

// List Key Roles
//
// Get all roles the key is in
func (client *ApiClient) ListKeyRoles(keyId string, queryParameters *models.ListKeyRolesParams) (*models.PaginatedListKeyRolesResponse, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.PageSize != nil {
			pageSizeStr := fmt.Sprintf("%v", *queryParameters.PageSize)
			queryParams["page.size"] = pageSizeStr
		}
		if queryParameters.PageStart != nil {
			queryParams["page.start"] = *queryParameters.PageStart
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "GET",
		path:        "/v0/org/{org_id}/keys/{key_id}/roles",
		pathParams:  map[string]string{"key_id": keyId},
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PaginatedListKeyRolesResponse](resp)
}

// List Historical Transactions
//
// Returns a sorted, paginated list of transactions signed by a given key,
// ordered from most recent first.
func (client *ApiClient) ListHistoricalKeyTx(keyId string, queryParameters *models.ListHistoricalKeyTxParams) (*models.PaginatedListHistoricalTxResponse, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.PageSize != nil {
			pageSizeStr := fmt.Sprintf("%v", *queryParameters.PageSize)
			queryParams["page.size"] = pageSizeStr
		}
		if queryParameters.PageStart != nil {
			queryParams["page.start"] = *queryParameters.PageStart
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "GET",
		path:        "/v0/org/{org_id}/keys/{key_id}/tx",
		pathParams:  map[string]string{"key_id": keyId},
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PaginatedListHistoricalTxResponse](resp)
}

// Get Key by Material ID
//
// Returns the properties of a key.
func (client *ApiClient) GetKeyByMaterialId(keyType string, materialId string) (*models.KeyInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "GET",
		path:       "/v0/org/{org_id}/keys/{key_type}/{material_id}",
		pathParams: map[string]string{"key_type": keyType, "material_id": materialId},
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.KeyInfo](resp)
}

// Query org metrics.
//
// Metrics summarize usage information about your CubeSigner organization over time. For example,
// you can call this endpoint find out:
//
//   - the average number of keys over the last month,
//   - the average number monthly users over the last year,
//   - the total number of transactions signed last week,
//   - how the number of different API requests was trending day-by-day over the last week/month/year, etc.
//
// Each metric kind can have one or more dimensions, to further specify the org property it describes.
// For example, the `UserCount` metrics have a membership dimensions to specify the kind of user membership
// in the organization ("Owner" vs. "Member" vs. "Alien").
func (client *ApiClient) QueryMetrics(queryParameters *models.QueryMetricsParams, queryMetricsRequest models.QueryMetricsRequest) (*models.PaginatedQueryMetricsResponse, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.PageSize != nil {
			pageSizeStr := fmt.Sprintf("%v", *queryParameters.PageSize)
			queryParams["page.size"] = pageSizeStr
		}
		if queryParameters.PageStart != nil {
			queryParams["page.start"] = *queryParameters.PageStart
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/metrics",
		queryParams: queryParams,
		body:        queryMetricsRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PaginatedQueryMetricsResponse](resp)
}

// List Pending MFA Requests
//
// Retrieves and returns all pending MFA requests that are accessible to the current session,
// i.e., those created by the current session identity plus those in which the current user
// is listed as an approver
func (client *ApiClient) MfaList() (*models.ListMfaResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "GET",
		path:   "/v0/org/{org_id}/mfa",
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.ListMfaResponse](resp)
}

// Get Pending MFA Request
//
// Retrieves and returns a pending MFA request by its id.
func (client *ApiClient) MfaGet(mfaId string) (*models.MfaRequestInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "GET",
		path:       "/v0/org/{org_id}/mfa/{mfa_id}",
		pathParams: map[string]string{"mfa_id": mfaId},
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.MfaRequestInfo](resp)
}

// Approve or Reject MFA Request
//
// Approve or reject request after logging in with CubeSigner.
//
// If approving, adds the currently-logged user as an approver
// of a pending MFA request of the [Status::RequiredApprovers] kind. If the required number of
// approvers is reached, the MFA request is approved; the confirmation receipt can be used to
// resume the original HTTP request.
//
// If rejecting, immediately deletes the pending MFA request.
func (client *ApiClient) MfaVoteCs(mfaId string, queryParameters *models.MfaVoteCsParams) (*models.MfaRequestInfo, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.MfaVote != nil {
			mfaVoteStr := fmt.Sprintf("%v", *queryParameters.MfaVote)
			queryParams["mfa_vote"] = mfaVoteStr
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "PATCH",
		path:        "/v0/org/{org_id}/mfa/{mfa_id}",
		pathParams:  map[string]string{"mfa_id": mfaId},
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.MfaRequestInfo](resp)
}

// Finalize a Email OTP MFA Approval/Rejection.
//
// The request should contain the full JWT obtained by concatenating the
// partial token returned by the `mfa_email_init` endpoint and the signature
// emailed to the user issuing the request.
//
// If approving, adds an approver to a pending MFA request.
// If the required number of approvers is reached, the MFA request is approved;
// the confirmation receipt can be used to resume the original HTTP request.
//
// If rejecting, immediately deletes the pending MFA request.
func (client *ApiClient) MfaVoteEmailComplete(mfaId string, emailOtpAnswer models.EmailOtpAnswer) (*models.MfaRequestInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "PATCH",
		path:       "/v0/org/{org_id}/mfa/{mfa_id}/email",
		pathParams: map[string]string{"mfa_id": mfaId},
		body:       emailOtpAnswer,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.MfaRequestInfo](resp)
}

// Initiate a FIDO MFA Approval/Rejection
//
// Initiates the approval/rejection process of an MFA Request using FIDO.
func (client *ApiClient) MfaFidoInit(mfaId string) (*models.FidoAssertChallenge, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "POST",
		path:       "/v0/org/{org_id}/mfa/{mfa_id}/fido",
		pathParams: map[string]string{"mfa_id": mfaId},
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.FidoAssertChallenge](resp)
}

// Finalize a FIDO MFA Approval/Rejection
//
// If approving, adds an approver to a pending MFA request.
// If the required number of approvers is reached, the MFA request is approved;
// the confirmation receipt can be used to resume the original HTTP request.
//
// If rejecting, immediately deletes the pending MFA request.
func (client *ApiClient) MfaVoteFidoComplete(mfaId string, queryParameters *models.MfaVoteFidoCompleteParams, fidoAssertAnswer models.FidoAssertAnswer) (*models.MfaRequestInfo, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.MfaVote != nil {
			mfaVoteStr := fmt.Sprintf("%v", *queryParameters.MfaVote)
			queryParams["mfa_vote"] = mfaVoteStr
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "PATCH",
		path:        "/v0/org/{org_id}/mfa/{mfa_id}/fido",
		pathParams:  map[string]string{"mfa_id": mfaId},
		queryParams: queryParams,
		body:        fidoAssertAnswer,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.MfaRequestInfo](resp)
}

// Approve/Reject a TOTP MFA Request
//
// If approving, adds the current user as approver to a pending MFA request by
// providing TOTP code. If the required number of approvers is reached, the MFA request is
// approved; the confirmation receipt can be used to resume the original HTTP request.
//
// If rejecting, immediately deletes the pending MFA request.
func (client *ApiClient) MfaVoteTotp(mfaId string, queryParameters *models.MfaVoteTotpParams, totpApproveRequest models.TotpApproveRequest) (*models.MfaRequestInfo, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.MfaVote != nil {
			mfaVoteStr := fmt.Sprintf("%v", *queryParameters.MfaVote)
			queryParams["mfa_vote"] = mfaVoteStr
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "PATCH",
		path:        "/v0/org/{org_id}/mfa/{mfa_id}/totp",
		pathParams:  map[string]string{"mfa_id": mfaId},
		queryParams: queryParams,
		body:        totpApproveRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.MfaRequestInfo](resp)
}

// Mint an OIDC ID token for Twitter
//
// This function acts identically to Twitter's [`oauth2/token`](https://developer.twitter.com/en/docs/authentication/api-reference/token) endpoint,
// but extends the output with an `id_token`.
//
// This `id_token` can then be used with any CubeSigner endpoint that requires an OIDC token.
//
//	> [!IMPORTANT]
//	> This endpoint will fail unless the org is configured to allow the issuer `https://shim.oauth2.cubist.dev/twitter` and client ID being used for Twitter.
func Oauth2Twitter(env session.EnvInterface, orgId string, requestBody any) (*models.TokenResponse, error) {
	client, err := NewApiClient(&noSessionManager{OrgID: orgId, RootUrl: env.Spec.SignerApiRoot})
	if err != nil {
		return nil, err
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/oauth2/twitter",
		body:   requestBody,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.TokenResponse](resp)
}

// Initiate login via email token
//
// This endpoint generates an OIDC token without a signature (of the form `header.payload.`), and sends the signature to the user's email.
// Client applications can reconstruct the token by concatenating the `partial_token` with the signature, producing a valid OIDC token of the form `header.payload.signature`
// The token can then be used to authenticate the user.
//
//	> [!IMPORTANT]
//	> For this endpoint to succeed, the org must be configured to:
//	> 1. Allow the issuer `https://shim.oauth2.cubist.dev/email-otp` and client ID being the Org ID
//	> 2. Have an email sender configured for OTPs
func EmailOtpAuth(env session.EnvInterface, orgId string, emailOtpRequest models.EmailOtpRequest) (*models.EmailOtpResponse, error) {
	client, err := NewApiClient(&noSessionManager{OrgID: orgId, RootUrl: env.Spec.SignerApiRoot})
	if err != nil {
		return nil, err
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/oidc/email-otp",
		body:   emailOtpRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmailOtpResponse](resp)
}

// Allows a user to authenticate with the telegram API using the tgWebAppData value
// The token has the following properties:
//   - The `sub` field is the telegram user ID
//   - The `iss` field depends on the chosen environment:
//   - `https://shim.oauth2.cubist.dev/telegram/production` for the production environment
//   - `https://shim.oauth2.cubist.dev/telegram/test` for the test environment
//   - The `aud` field is the provided telegram bot ID
//   - The `exp` field is derived from the `auth_date` field in the telegram data
//
// Fails if the telegram data is invalid or the signature is invalid
func TelegramAuth(env session.EnvInterface, orgId string, telegramAuthRequest models.TelegramAuthRequest) (*models.TelegramAuthResponse, error) {
	client, err := NewApiClient(&noSessionManager{OrgID: orgId, RootUrl: env.Spec.SignerApiRoot})
	if err != nil {
		return nil, err
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/oidc/telegram",
		body:   telegramAuthRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.TelegramAuthResponse](resp)
}

// Create Org
//
// Creates a new organization. The new org is a child of the
// current org and inherits its key-export policy. The new org
// is created with one owner, the caller of this API.
func (client *ApiClient) CreateOrg(createOrgRequest models.CreateOrgRequest) (*models.OrgInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/orgs",
		body:   createOrgRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.OrgInfo](resp)
}

// List Policies
//
// Returns the list of all policies in the Org.
func (client *ApiClient) ListPolicies(queryParameters *models.ListPoliciesParams) (*models.PaginatedListPoliciesResponse, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.PageSize != nil {
			pageSizeStr := fmt.Sprintf("%v", *queryParameters.PageSize)
			queryParams["page.size"] = pageSizeStr
		}
		if queryParameters.PageStart != nil {
			queryParams["page.start"] = *queryParameters.PageStart
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "GET",
		path:        "/v0/org/{org_id}/policies",
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PaginatedListPoliciesResponse](resp)
}

// Create Policy
//
// Creates a new named policy in the organization. The user making the request is the
// owner of the policy, giving them edit access to the policy along with the org owners.
func (client *ApiClient) CreatePolicy(createPolicyRequest models.CreatePolicyRequest) (*models.PolicyInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/policies",
		body:   createPolicyRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PolicyInfo](resp)
}

// Delete Policy
//
// Delete the named policy with the given name or id.
func (client *ApiClient) DeletePolicy(policyId string, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.EmptyImpl], error) {
	resp, err := client.send(&payload{
		method:      "DELETE",
		path:        "/v0/org/{org_id}/policies/{policy_id}",
		pathParams:  map[string]string{"policy_id": policyId},
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.EmptyImpl](resp)
}

// Update Policy
//
// Updates the policy with the given name or id.
func (client *ApiClient) UpdatePolicy(policyId string, updatePolicyRequest models.UpdatePolicyRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.PolicyInfo], error) {
	resp, err := client.send(&payload{
		method:      "PATCH",
		path:        "/v0/org/{org_id}/policies/{policy_id}",
		pathParams:  map[string]string{"policy_id": policyId},
		body:        updatePolicyRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.PolicyInfo](resp)
}

// Get Policy Logs
//
// Returns the logs for the given policy, within the given timeframe.
func (client *ApiClient) GetPolicyLogs(policyId string, queryParameters *models.GetPolicyLogsParams, policyLogsRequest models.PolicyLogsRequest) (*models.PaginatedPolicyLogsResponse, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.PageSize != nil {
			pageSizeStr := fmt.Sprintf("%v", *queryParameters.PageSize)
			queryParams["page.size"] = pageSizeStr
		}
		if queryParameters.PageStart != nil {
			queryParams["page.start"] = *queryParameters.PageStart
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/policies/{policy_id}/logs",
		pathParams:  map[string]string{"policy_id": policyId},
		queryParams: queryParams,
		body:        policyLogsRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PaginatedPolicyLogsResponse](resp)
}

// Get Policy
//
// Returns the specified version or latest of a named policy with the given name or id.
func (client *ApiClient) GetPolicy(policyId string, version string) (*models.PolicyInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "GET",
		path:       "/v0/org/{org_id}/policies/{policy_id}/{version}",
		pathParams: map[string]string{"policy_id": policyId, "version": version},
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PolicyInfo](resp)
}

// Invoke Policy
//
// Invokes the [NamedPolicy] with the given ID with the given request information.
// It is only supported for Wasm policies.
func (client *ApiClient) InvokePolicy(policyId string, version string, invokePolicyRequest models.InvokePolicyRequest) (*models.InvokePolicyResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "POST",
		path:       "/v0/org/{org_id}/policies/{policy_id}/{version}/invoke",
		pathParams: map[string]string{"policy_id": policyId, "version": version},
		body:       invokePolicyRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.InvokePolicyResponse](resp)
}

// Create Policy Import Key
//
// Generate an ephemeral key that a client can use for encrypting data related to Wasm
// policies (e.g., policy secrets).
func (client *ApiClient) CreatePolicyImportKey() (*models.CreatePolicyImportKeyResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "GET",
		path:   "/v0/org/{org_id}/policy/import_key",
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.CreatePolicyImportKeyResponse](resp)
}

// Get the org-wide policy secrets.
//
// Note that this only returns the keys for the secrets, omiting the values.
// The values are secret and are not accessible outside Wasm policy execution.
func (client *ApiClient) GetPolicySecrets() (*models.PolicySecretsInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "GET",
		path:   "/v0/org/{org_id}/policy/secrets",
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PolicySecretsInfo](resp)
}

// Update org-level policy secrets
//
// The provided secrets will replace any existing org-level secrets.
// It fails if the secrets weren't previously created.
func (client *ApiClient) UpdatePolicySecrets(updatePolicySecretsRequest models.UpdatePolicySecretsRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.PolicySecretsInfo], error) {
	resp, err := client.send(&payload{
		method:      "PATCH",
		path:        "/v0/org/{org_id}/policy/secrets",
		body:        updatePolicySecretsRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.PolicySecretsInfo](resp)
}

// Create or overwrite an org-level policy secret
func (client *ApiClient) SetPolicySecret(secretName string, setPolicySecretRequest models.SetPolicySecretRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.PolicySecretsInfo], error) {
	resp, err := client.send(&payload{
		method:      "PUT",
		path:        "/v0/org/{org_id}/policy/secrets/{secret_name}",
		pathParams:  map[string]string{"secret_name": secretName},
		body:        setPolicySecretRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.PolicySecretsInfo](resp)
}

// Delete an org-level policy secret
func (client *ApiClient) DeletePolicySecret(secretName string, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.PolicySecretsInfo], error) {
	resp, err := client.send(&payload{
		method:      "DELETE",
		path:        "/v0/org/{org_id}/policy/secrets/{secret_name}",
		pathParams:  map[string]string{"secret_name": secretName},
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.PolicySecretsInfo](resp)
}

// Upload Wasm Policy
//
// Returns a signed URL for uploading a wasm policy to CubeSigner. The policy will be
// deleted if not attached to a [NamedPolicy] soon after the upload has been completed.
func (client *ApiClient) UploadWasmPolicy(uploadWasmPolicyRequest models.UploadWasmPolicyRequest) (*models.UploadWasmPolicyResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/policy/wasm",
		body:   uploadWasmPolicyRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.UploadWasmPolicyResponse](resp)
}

// List Roles
//
// Retrieves all roles in an organization that the current user is allowed to access.
func (client *ApiClient) ListRoles(queryParameters *models.ListRolesParams) (*models.PaginatedListRolesResponse, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.PageSize != nil {
			pageSizeStr := fmt.Sprintf("%v", *queryParameters.PageSize)
			queryParams["page.size"] = pageSizeStr
		}
		if queryParameters.PageStart != nil {
			queryParams["page.start"] = *queryParameters.PageStart
		}
		if queryParameters.Summarize != nil {
			summarizeStr := fmt.Sprintf("%v", *queryParameters.Summarize)
			queryParams["summarize"] = summarizeStr
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "GET",
		path:        "/v0/org/{org_id}/roles",
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PaginatedListRolesResponse](resp)
}

// Create Role
//
// Creates a new role in an organization. Unless the logged-in user
// is the owner, they are automatically added to the newly created role.
func (client *ApiClient) CreateRole(createRoleRequest *models.CreateRoleRequest) (*models.CreateRoleResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/roles",
		body:   createRoleRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.CreateRoleResponse](resp)
}

// Get Role
//
// Retrieves information about a role in an organization
func (client *ApiClient) GetRole(roleId string) (*models.RoleInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "GET",
		path:       "/v0/org/{org_id}/roles/{role_id}",
		pathParams: map[string]string{"role_id": roleId},
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.RoleInfo](resp)
}

// Delete Role
//
// Deletes a role in an organization.
//
// Only users in the role can perform this action.
// Additionally, the role's edit policy (if set) must permit the update.
func (client *ApiClient) DeleteRole(roleId string, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.EmptyImpl], error) {
	resp, err := client.send(&payload{
		method:      "DELETE",
		path:        "/v0/org/{org_id}/roles/{role_id}",
		pathParams:  map[string]string{"role_id": roleId},
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.EmptyImpl](resp)
}

// Update Role
//
// Enables or disables a role (this requires the `manage:role:update:enable` scope).
// Updates the role's policies (this requires the `manage:role:update:policy` scope).
// Updates the role's edit policies (this requires the `manage:role:update:editPolicy` scope).
//
// The user must be in the role or an owner of the organization.
// Additionally, the role's edit policy (if set) must permit the update.
func (client *ApiClient) UpdateRole(roleId string, updateRoleRequest models.UpdateRoleRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.RoleInfo], error) {
	resp, err := client.send(&payload{
		method:      "PATCH",
		path:        "/v0/org/{org_id}/roles/{role_id}",
		pathParams:  map[string]string{"role_id": roleId},
		body:        updateRoleRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.RoleInfo](resp)
}

// Add Keys
//
// Adds a list of existing keys to an existing role.
//
// The key owner is allowed to add their key to any role that they are in.
//
// In "org custody" model only, org owners are allowed to add any key to any role.
//
// In all cases: the role's edit policy, as well as the edit policy of each of the keys, must permit the update.
//
// Each request to this endpoint can add, at maximum, 32 keys.
func (client *ApiClient) AddKeysToRole(roleId string, addKeysToRoleRequest models.AddKeysToRoleRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.EmptyImpl], error) {
	resp, err := client.send(&payload{
		method:      "PUT",
		path:        "/v0/org/{org_id}/roles/{role_id}/add_keys",
		pathParams:  map[string]string{"role_id": roleId},
		body:        addKeysToRoleRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.EmptyImpl](resp)
}

// Add User
//
// Adds an existing user to an existing role.
//
// Only users in the role or org owners can add users to a role.
// Additionally, the role's edit policy (if set) must permit the update.
func (client *ApiClient) AddUserToRole(roleId string, userId string, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.EmptyImpl], error) {
	resp, err := client.send(&payload{
		method:      "PUT",
		path:        "/v0/org/{org_id}/roles/{role_id}/add_user/{user_id}",
		pathParams:  map[string]string{"role_id": roleId, "user_id": userId},
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.EmptyImpl](resp)
}

// List Role Keys
//
// Returns an array of all keys in a role.
func (client *ApiClient) ListRoleKeys(roleId string, queryParameters *models.ListRoleKeysParams) (*models.PaginatedListRoleKeysResponse, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.PageSize != nil {
			pageSizeStr := fmt.Sprintf("%v", *queryParameters.PageSize)
			queryParams["page.size"] = pageSizeStr
		}
		if queryParameters.PageStart != nil {
			queryParams["page.start"] = *queryParameters.PageStart
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "GET",
		path:        "/v0/org/{org_id}/roles/{role_id}/keys",
		pathParams:  map[string]string{"role_id": roleId},
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PaginatedListRoleKeysResponse](resp)
}

// Get a Key in Role
//
// Returns the key-in-role information for a given key and role
func (client *ApiClient) GetRoleKey(roleId string, keyId string) (*models.KeyInRoleInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "GET",
		path:       "/v0/org/{org_id}/roles/{role_id}/keys/{key_id}",
		pathParams: map[string]string{"role_id": roleId, "key_id": keyId},
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.KeyInRoleInfo](resp)
}

// Remove Key
//
// Removes a given key from a role.
//
// Only users in the role or org owners can remove keys from a role.
// Additionally, both the role's and the key's edit policy must permit the update.
func (client *ApiClient) RemoveKeyFromRole(roleId string, keyId string, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.EmptyImpl], error) {
	resp, err := client.send(&payload{
		method:      "DELETE",
		path:        "/v0/org/{org_id}/roles/{role_id}/keys/{key_id}",
		pathParams:  map[string]string{"role_id": roleId, "key_id": keyId},
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.EmptyImpl](resp)
}

// Create Token
//
// Creates a new access token for a given role (to be used as "API Key" for all signing actions).
// The `restricted_actions` field on the [Role] determines the membership role that is required to
// create tokens.
func (client *ApiClient) CreateRoleToken(roleId string, createTokenRequest models.CreateTokenRequest) (*models.NewSessionResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "POST",
		path:       "/v0/org/{org_id}/roles/{role_id}/tokens",
		pathParams: map[string]string{"role_id": roleId},
		body:       createTokenRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.NewSessionResponse](resp)
}

// List Historical Transactions
//
// Returns a sorted, paginated list of transactions signed by the given role,
// ordered from most recent first.
func (client *ApiClient) ListHistoricalRoleTx(roleId string, queryParameters *models.ListHistoricalRoleTxParams) (*models.PaginatedListHistoricalTxResponse, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.PageSize != nil {
			pageSizeStr := fmt.Sprintf("%v", *queryParameters.PageSize)
			queryParams["page.size"] = pageSizeStr
		}
		if queryParameters.PageStart != nil {
			queryParams["page.start"] = *queryParameters.PageStart
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "GET",
		path:        "/v0/org/{org_id}/roles/{role_id}/tx",
		pathParams:  map[string]string{"role_id": roleId},
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PaginatedListHistoricalTxResponse](resp)
}

// List Role Users.
//
// Returns an array of all users who have access to a role.
func (client *ApiClient) ListRoleUsers(roleId string, queryParameters *models.ListRoleUsersParams) (*models.PaginatedListRoleUsersResponse, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.PageSize != nil {
			pageSizeStr := fmt.Sprintf("%v", *queryParameters.PageSize)
			queryParams["page.size"] = pageSizeStr
		}
		if queryParameters.PageStart != nil {
			queryParams["page.start"] = *queryParameters.PageStart
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "GET",
		path:        "/v0/org/{org_id}/roles/{role_id}/users",
		pathParams:  map[string]string{"role_id": roleId},
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PaginatedListRoleUsersResponse](resp)
}

// Remove User
//
// Removes an existing user from an existing role.
//
// Only users in the role or org owners can remove users from a role.
// Additionally, the role's edit policy (if set) must permit the update.
func (client *ApiClient) RemoveUserFromRole(roleId string, userId string, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.EmptyImpl], error) {
	resp, err := client.send(&payload{
		method:      "DELETE",
		path:        "/v0/org/{org_id}/roles/{role_id}/users/{user_id}",
		pathParams:  map[string]string{"role_id": roleId, "user_id": userId},
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.EmptyImpl](resp)
}

// List sessions
//
// If no query parameters are provided, all active sessions for the current user are returned.
//
// If a `role` query parameter is provided, all active sessions for the selected role are returned
// (asserting first that the current user has permissions to read sessions for that role).
func (client *ApiClient) ListSessions(queryParameters *models.ListSessionsParams) (*models.PaginatedSessionsResponse, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.PageSize != nil {
			pageSizeStr := fmt.Sprintf("%v", *queryParameters.PageSize)
			queryParams["page.size"] = pageSizeStr
		}
		if queryParameters.PageStart != nil {
			queryParams["page.start"] = *queryParameters.PageStart
		}
		if queryParameters.Role != nil {
			queryParams["role"] = *queryParameters.Role
		}
		if queryParameters.User != nil {
			queryParams["user"] = *queryParameters.User
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "GET",
		path:        "/v0/org/{org_id}/session",
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PaginatedSessionsResponse](resp)
}

// Revoke ALL existing user or role session(s)
//
// Immediately revokes existing sessions, preventing them from being used or refreshed.
//
// If no query params are provided, **ALL** sessions for the **CURRENT USER** are revoked
// (to revoke just the current user session, use `DELETE /v0/org/<org_id>/session/self`)
//
// If a `role` query parameter is provided, **ALL** session for **THAT ROLE** are revoked
// (if the current user has permissions to revoke sessions for the role).
func (client *ApiClient) RevokeSessions(queryParameters *models.RevokeSessionsParams) (*models.SessionsResponse, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.Role != nil {
			queryParams["role"] = *queryParameters.Role
		}
		if queryParameters.User != nil {
			queryParams["user"] = *queryParameters.User
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "DELETE",
		path:        "/v0/org/{org_id}/session",
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.SessionsResponse](resp)
}

// Revoke current session
//
// Immediately revokes the current session, preventing it from being used or refreshed
func (client *ApiClient) RevokeCurrentSession() (*models.EmptyImpl, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "DELETE",
		path:   "/v0/org/{org_id}/session/self",
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Get session information
func (client *ApiClient) GetSession(sessionId string) (*models.SessionInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "GET",
		path:       "/v0/org/{org_id}/session/{session_id}",
		pathParams: map[string]string{"session_id": sessionId},
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.SessionInfo](resp)
}

// Revoke a session
//
// Immediately revokes an existing session, preventing it from being used or refreshed
func (client *ApiClient) RevokeSession(sessionId string) (*models.SessionInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "DELETE",
		path:       "/v0/org/{org_id}/session/{session_id}",
		pathParams: map[string]string{"session_id": sessionId},
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.SessionInfo](resp)
}

// Sign Solana Message
//
// Signs a Solana message with a given key.
// This is a pre-release feature.
func (client *ApiClient) SolanaSign(pubkey string, solanaSignRequest models.SolanaSignRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.SignResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/solana/sign/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        solanaSignRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.SignResponse](resp)
}

// Sign a serialized SUI transaction.
//
// This is a pre-release feature.
func (client *ApiClient) SuiSign(pubkey string, suiSignRequest models.SuiSignRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.SignResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/sui/sign/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        suiSignRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.SignResponse](resp)
}

// Sign a tendermint message.
//
// Signs the given base-64 encoded vote or proposal with the given tendermint key.
func (client *ApiClient) TendermintSign(pubkey string, tendermintSignRequest models.TendermintSignRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.SignResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/tendermint/sign/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        tendermintSignRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.SignResponse](resp)
}

// Get Token-Accessible Keys
//
// Retrieves the keys that a user or role session can access.
func (client *ApiClient) ListTokenKeys() (*models.KeyInfos, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "GET",
		path:   "/v0/org/{org_id}/token/keys",
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.KeyInfos](resp)
}

// User Info
//
// Retrieves information about the current user.
func (client *ApiClient) AboutMe() (*models.UserInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "GET",
		path:   "/v0/org/{org_id}/user/me",
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.UserInfo](resp)
}

// List outstanding user-export requests
func (client *ApiClient) UserExportList(queryParameters *models.UserExportListParams) (*models.PaginatedUserExportListResponse, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.PageSize != nil {
			pageSizeStr := fmt.Sprintf("%v", *queryParameters.PageSize)
			queryParams["page.size"] = pageSizeStr
		}
		if queryParameters.PageStart != nil {
			queryParams["page.start"] = *queryParameters.PageStart
		}
		if queryParameters.UserId != nil {
			queryParams["user_id"] = *queryParameters.UserId
		}
		if queryParameters.KeyId != nil {
			queryParams["key_id"] = *queryParameters.KeyId
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "GET",
		path:        "/v0/org/{org_id}/user/me/export",
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PaginatedUserExportListResponse](resp)
}

// Initiate a user-export request
//
// This starts a delay (whose length is determined by Org-wide settings)
// before export can be completed, and returns a ticket that can be used
// to complete the export once the timer has expired.
//
// Only one user-export request can be active for a given key. If there
// is already an active export, this endpoint will return an error. To
// create a new request, first delete the existing one.
func (client *ApiClient) UserExportInit(userExportInitRequest models.UserExportInitRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.UserExportInitResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/user/me/export",
		body:        userExportInitRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.UserExportInitResponse](resp)
}

// Delete an existing user-export request
func (client *ApiClient) UserExportDelete(queryParameters models.UserExportDeleteParams) (*models.EmptyImpl, error) {
	queryParams := make(map[string]string)
	queryParams["key_id"] = queryParameters.KeyId
	if queryParameters.UserId != nil {
		queryParams["user_id"] = *queryParameters.UserId
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "DELETE",
		path:        "/v0/org/{org_id}/user/me/export",
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Complete a user-export request
//
// This endpoint can be called only after initiating a user-export request via
// the `user_export_init` API, and only within the subsequent export window
// (i.e., after the export delay has passed and before the request has expired).
//
// To check on the status of an export request, see the `user_export_list` API.
func (client *ApiClient) UserExportComplete(userExportCompleteRequest models.UserExportCompleteRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.UserExportCompleteResponse], error) {
	resp, err := client.send(&payload{
		method:      "PATCH",
		path:        "/v0/org/{org_id}/user/me/export",
		body:        userExportCompleteRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.UserExportCompleteResponse](resp)
}

// Initiate registration of a FIDO key
//
// Generates a challenge that must be answered to prove ownership of a key
func (client *ApiClient) UserRegisterFidoInit(fidoCreateRequest models.FidoCreateRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.FidoCreateChallengeResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/user/me/fido",
		body:        fidoCreateRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.FidoCreateChallengeResponse](resp)
}

// Finalize registration of a FIDO key
//
// Accepts the response to the challenge generated by the POST to this endpoint.
func (client *ApiClient) UserRegisterFidoComplete(fidoCreateChallengeAnswer models.FidoCreateChallengeAnswer) (*models.EmptyImpl, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "PATCH",
		path:   "/v0/org/{org_id}/user/me/fido",
		body:   fidoCreateChallengeAnswer,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Delete FIDO key
//
// Deletes a FIDO key from the user's account (if the key is not the sole MFA factor). MFA is always required.
func (client *ApiClient) UserDeleteFido(fidoId string, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.EmptyImpl], error) {
	resp, err := client.send(&payload{
		method:      "DELETE",
		path:        "/v0/org/{org_id}/user/me/fido/{fido_id}",
		pathParams:  map[string]string{"fido_id": fidoId},
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.EmptyImpl](resp)
}

// Initialize TOTP Reset
//
// Creates a new TOTP challenge that must be answered to prove that the new TOTP
// was successfully imported into an authenticator app.
//
// This operation is allowed if EITHER
//   - the user account is not yet initialized and no TOTP is already set, OR
//   - the user has not configured any auth factors;
//
// otherwise, MFA is required.
func (client *ApiClient) UserResetTotpInit(totpResetRequest *models.TotpResetRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.TotpInfo], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/org/{org_id}/user/me/totp",
		body:        totpResetRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.TotpInfo](resp)
}

// Delete TOTP
//
// Deletes TOTP from the user's account (if TOTP is not the sole MFA factor). MFA is always required.
func (client *ApiClient) UserDeleteTotp(mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.EmptyImpl], error) {
	resp, err := client.send(&payload{
		method:      "DELETE",
		path:        "/v0/org/{org_id}/user/me/totp",
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.EmptyImpl](resp)
}

// Finalize resetting TOTP
//
// Checks if the response contains the correct TOTP code corresponding to the
// challenge generated by the POST method of this endpoint.
func (client *ApiClient) UserResetTotpComplete(totpChallengeAnswer models.TotpChallengeAnswer) (*models.EmptyImpl, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "PATCH",
		path:   "/v0/org/{org_id}/user/me/totp",
		body:   totpChallengeAnswer,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Verify TOTP
//
// Checks if a given code matches the current TOTP code for the current user.
// Errors with 403 if the current user has not set up TOTP or the code fails verification.
func (client *ApiClient) UserVerifyTotp(totpApproveRequest models.TotpApproveRequest) (*models.EmptyImpl, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/user/me/totp/verify",
		body:   totpApproveRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// List users in organization
func (client *ApiClient) ListUsersInOrg(queryParameters *models.ListUsersInOrgParams) (*models.PaginatedGetUsersInOrgResponse, error) {
	queryParams := make(map[string]string)
	if queryParameters != nil {
		if queryParameters.PageSize != nil {
			pageSizeStr := fmt.Sprintf("%v", *queryParameters.PageSize)
			queryParams["page.size"] = pageSizeStr
		}
		if queryParameters.PageStart != nil {
			queryParams["page.start"] = *queryParameters.PageStart
		}
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:      "GET",
		path:        "/v0/org/{org_id}/users",
		queryParams: queryParams,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PaginatedGetUsersInOrgResponse](resp)
}

// Add a third-party user to the org
func (client *ApiClient) CreateOidcUser(addThirdPartyUserRequest models.AddThirdPartyUserRequest) (*models.AddThirdPartyUserResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/org/{org_id}/users",
		body:   addThirdPartyUserRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.AddThirdPartyUserResponse](resp)
}

// Remove a third-party user from the org
func (client *ApiClient) DeleteOidcUser(oidcIdentity models.OidcIdentity) (*models.EmptyImpl, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "DELETE",
		path:   "/v0/org/{org_id}/users/oidc",
		body:   oidcIdentity,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Get user by id
func (client *ApiClient) GetUserInOrg(userId string) (*models.UserInOrgInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "GET",
		path:       "/v0/org/{org_id}/users/{user_id}",
		pathParams: map[string]string{"user_id": userId},
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.UserInOrgInfo](resp)
}

// Remove a user from the org
func (client *ApiClient) DeleteUser(userId string) (*models.EmptyImpl, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "DELETE",
		path:       "/v0/org/{org_id}/users/{user_id}",
		pathParams: map[string]string{"user_id": userId},
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Update a user's membership in the org
//
// Enable/disable another user in the org, or change their membership role.
func (client *ApiClient) UpdateUserMembership(userId string, updateUserMembershipRequest models.UpdateUserMembershipRequest) (*models.UserInOrgInfo, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "PATCH",
		path:       "/v0/org/{org_id}/users/{user_id}/membership",
		pathParams: map[string]string{"user_id": userId},
		body:       updateUserMembershipRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.UserInOrgInfo](resp)
}

// Initiate Login with Passkey
//
// The response contains a FIDO challenge that the client must answer with any of their
// discoverable credentials.  The answer should be submitted with the corresponding PATCH request.
func PasskeyAuthInit(env session.EnvInterface, loginRequest models.LoginRequest) (*models.PasskeyAssertChallenge, error) {
	client, err := NewApiClient(&noSessionManager{RootUrl: env.Spec.SignerApiRoot})
	if err != nil {
		return nil, err
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/passkey",
		body:   loginRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PasskeyAssertChallenge](resp)
}

// Complete Login with Passkey
//
// The request should contain an answer to the challenge issued by the corresponding POST request.
// The challenge may be answered with any of the user's discoverable credentials; if the credential
// included in the answer is registered with a user and an organization, the response will contain
// a CubeSigner session (with the parameters supplied in the previous POST request) for that user
// in that organization.
func PasskeyAuthComplete(env session.EnvInterface, passkeyAssertAnswer models.PasskeyAssertAnswer) (*models.NewSessionResponse, error) {
	client, err := NewApiClient(&noSessionManager{RootUrl: env.Spec.SignerApiRoot})
	if err != nil {
		return nil, err
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "PATCH",
		path:   "/v0/passkey",
		body:   passkeyAssertAnswer,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.NewSessionResponse](resp)
}

// The policy_execute API endpoint is intended to demonstrate that the signer
// can use the policy engine, by way of the PolicyEngineClient.
func (client *ApiClient) PolicyExecute(policyName string, requestBody any) (*models.PolicyResultResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:     "POST",
		path:       "/v0/private/policy-execute/{policy_name}",
		pathParams: map[string]string{"policy_name": policyName},
		body:       requestBody,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.PolicyResultResponse](resp)
}

// Initiate registration of a FIDO key
//
// Generates a challenge that must be answered to prove ownership of a key
func (client *ApiClient) RegisterFidoInitLegacy(fidoCreateRequest models.FidoCreateRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.FidoCreateChallengeResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/user/me/fido",
		body:        fidoCreateRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.FidoCreateChallengeResponse](resp)
}

// Finalize registration of a FIDO key
//
// Accepts the response to the challenge generated by the POST to this endpoint.
func (client *ApiClient) RegisterFidoCompleteLegacy(fidoCreateChallengeAnswer models.FidoCreateChallengeAnswer) (*models.EmptyImpl, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "PATCH",
		path:   "/v0/user/me/fido",
		body:   fidoCreateChallengeAnswer,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Initialize TOTP Reset
//
// Creates a new TOTP challenge that must be answered to prove that the new TOTP
// was successfully imported into an authenticator app.
//
// This operation is allowed if EITHER
//   - the user account is not yet initialized and no TOTP is already set, OR
//   - the user has not configured any auth factors;
//
// otherwise, MFA is required.
func (client *ApiClient) ResetTotpInitLegacy(totpResetRequest *models.TotpResetRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.TotpInfo], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v0/user/me/totp",
		body:        totpResetRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.TotpInfo](resp)
}

// Finalize resetting TOTP
//
// Checks if the response contains the correct TOTP code corresponding to the
// challenge generated by the POST method of this endpoint.
func (client *ApiClient) ResetTotpCompleteLegacy(totpChallengeAnswer models.TotpChallengeAnswer) (*models.EmptyImpl, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "PATCH",
		path:   "/v0/user/me/totp",
		body:   totpChallengeAnswer,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Verify TOTP
//
// Checks if a given code matches the current TOTP code for the current user.
// Errors with 403 if the current user has not set up TOTP or the code fails verification.
func (client *ApiClient) VerifyTotpLegacy(totpApproveRequest models.TotpApproveRequest) (*models.EmptyImpl, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v0/user/me/totp/verify",
		body:   totpApproveRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Retrieves all the orgs the user is a part of
func UserOrgs(env session.EnvInterface, idToken string) (*models.UserOrgsResponse, error) {
	client, err := NewApiClient(&noSessionManager{RootUrl: env.Spec.SignerApiRoot})
	if err != nil {
		return nil, err
	}
	resp, err := client.sendAndAssertNoMfa(&payload{
		method:  "GET",
		path:    "/v0/user/orgs",
		headers: map[string]string{"Authorization": idToken},
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.UserOrgsResponse](resp)
}

// Sign Raw Blob
//
// Signs an arbitrary blob with a given key.
//
//   - ECDSA signatures are serialized as big-endian r and s plus recovery-id
//
// byte v, which can in general take any of the values 0, 1, 2, or 3.
//
//   - EdDSA signatures are serialized in the standard format.
//
//   - BLS signatures are not supported on the blob-sign endpoint.
func (client *ApiClient) BlobSign(keyId string, blobSignRequest models.BlobSignRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.SignResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v1/org/{org_id}/blob/sign/{key_id}",
		pathParams:  map[string]string{"key_id": keyId},
		body:        blobSignRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.SignResponse](resp)
}

// Record heartbeat
//
// This endpoint is called by the cube3signer proxy to record various metrics to CloudWatch.
func (client *ApiClient) Cube3signerHeartbeat(heartbeatRequest *models.HeartbeatRequest) (*models.EmptyImpl, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "POST",
		path:   "/v1/org/{org_id}/cube3signer/heartbeat",
		body:   heartbeatRequest,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.EmptyImpl](resp)
}

// Sign EVM Transaction
//
// Signs an Ethereum (and other EVM) transaction with a given Secp256k1 key.
// Returns an RLP-encoded transaction with EIP-155 signature.
//
// The key must be associated with the role and organization on whose behalf this action is called.
func (client *ApiClient) EvmSign(pubkey string, eth1SignRequest models.Eth1SignRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.Eth1SignResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v1/org/{org_id}/eth1/sign/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        eth1SignRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.Eth1SignResponse](resp)
}

// Sign Validator Request
//
// Signs an eth2 validator request with a given BLS key.
//
// The key must be associated with the role and organization on whose behalf this action is called.
func (client *ApiClient) Eth2Sign(pubkey string, eth2SignRequest models.Eth2SignRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.Eth2SignResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v1/org/{org_id}/eth2/sign/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        eth2SignRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.Eth2SignResponse](resp)
}

// Sign Stake Deposit
//
// Signs a deposit transaction with a `validator_key`. If `validator_key` is set to a pregenerated key, we use the
// provided validator key. Otherwise, we generate a new BLS key.
//
// When using a pregenerated key, the key must be associated with the role and organization on whose
// behalf this action is called.
func (client *ApiClient) Stake(stakeRequest models.StakeRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.StakeResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v1/org/{org_id}/eth2/stake",
		body:        stakeRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.StakeResponse](resp)
}

// Sign Unstake Request
//
// Handle unstaking request, producing a signed voluntary exit message
// that can be posted directly to the Beacon chain.
//
// The key must be associated with the role and organization on whose behalf this action is called.
func (client *ApiClient) Unstake(pubkey string, unstakeRequest models.UnstakeRequest, mfaReceipts ...*MfaReceipt) (*CubeSignerResponse[models.UnstakeResponse], error) {
	resp, err := client.send(&payload{
		method:      "POST",
		path:        "/v1/org/{org_id}/eth2/unstake/{pubkey}",
		pathParams:  map[string]string{"pubkey": pubkey},
		body:        unstakeRequest,
		mfaReceipts: mfaReceipts,
	})
	if err != nil {
		return nil, err
	}
	return newCubeSignerResponseFrom[models.UnstakeResponse](resp)
}

// Refresh Signer Session
func (client *ApiClient) SignerSessionRefresh(authData models.AuthData) (*models.NewSessionResponse, error) {
	resp, err := client.sendAndAssertNoMfa(&payload{
		method: "PATCH",
		path:   "/v1/org/{org_id}/token/refresh",
		body:   authData,
	})
	if err != nil {
		return nil, err
	}
	return ParseGenericResponseInto[models.NewSessionResponse](resp)
}
