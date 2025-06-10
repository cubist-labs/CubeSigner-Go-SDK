package client

import (
	"github.com/cubist-labs/cubesigner-go-sdk/models"
)

// CubeSignerMfaType returns [models.MfaType]
// of type CubeSigner.
func CubeSignerMfaType() models.MfaType {
	mfaType := models.MfaType{}
	_ = mfaType.FromMfaTypeCubeSigner(models.CubeSigner)
	return mfaType
}

// TotpMfaType returns a [models.MfaType]
// of type Totp
func TotpMfaType() models.MfaType {
	mfaType := models.MfaType{}
	_ = mfaType.FromMfaTypeTotp(models.Totp)
	return mfaType
}

// EmailOtpMfaType returns [models.MfaType]
// of type EmailOtp
func EmailOtpMfaType() models.MfaType {
	mfaType := models.MfaType{}
	_ = mfaType.FromMfaTypeEmailOtp(models.EmailOtp)
	return mfaType
}

// FidoMfaType returns [models.MfaType]
// of type Fido
func FidoMfaType() models.MfaType {
	mfaType := models.MfaType{}
	_ = mfaType.FromMfaTypeFido(models.Fido)
	return mfaType
}

// helper data structure used by the client
// when embedding confirmation receipts in request
// headers
type MfaReceipt struct {
	Id           string `json:"id"`
	Confirmation string `json:"confirmation"`
}

// MfaRequest.GetReceipt returns a receipt with MfaID that can be used to
// resubmit the original request. Returns nil if there is no receipt
// attached with the MfaRequest.
func GetReceipt(mfaRequest *models.MfaRequestInfo) *MfaReceipt {
	if mfaRequest.Receipt == nil {
		return nil
	}
	return &MfaReceipt{
		Id:           mfaRequest.Id,
		Confirmation: mfaRequest.Receipt.Confirmation,
	}
}

// RequireMfaPolicy describes an MFA policy. The policy options are
// under RequireMfa field.
type RequireMfaPolicy struct {
	RequireMfa *models.MfaPolicy `json:"RequireMfa,omitempty"`
}

// emailChallenge is returned by the
// MfaVoteEmailInit endpoint. This
// challenge can be answered with its
// Answer(emailOtp) method or with
// the MfaVoteEmailComplete endpoint.
type EmailChallenge struct {
	MfaId        string
	apiClient    *ApiClient
	PartialToken string
}

// emailChallenge.Answer invokes the MfaVoteEmailComplete endpoint to complete the challenge and return
// the approved MfaRequest.
func (challenge EmailChallenge) Answer(emailOtp string) (*models.MfaRequestInfo, error) {
	return challenge.apiClient.MfaVoteEmailComplete(challenge.MfaId, models.EmailOtpAnswer{Token: challenge.PartialToken + emailOtp})
}
