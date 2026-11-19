// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/casdoor/casdoor/i18n"
	"github.com/casdoor/casdoor/util"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// MfaRecoveryType is the pseudo factor of a recovery code in the audit record and the proof token
const MfaRecoveryType = "recovery"

// MfaProofLifetimeInSeconds is how long the proof of a step-up check can be presented
const MfaProofLifetimeInSeconds = 300

// MfaProofTokenType is the "typ" header of the proof of a step-up check: no access or ID token has it
const MfaProofTokenType = "mfa-proof+jwt"

const (
	maxMfaPasscodeLength = 256
	maxMfaProofClaimSize = 256
)

// The outcome of a step-up check, of a code sent for one, or of a change of the factors that needs one, is
// the "data" of the error response: the error mask (enableErrorMask2) replaces the message, not the data.
const (
	MfaOutcomeWrongCode      = "mfa-wrong-code"
	MfaOutcomeRateLimited    = "mfa-rate-limited"
	MfaOutcomeNotEnrolled    = "mfa-not-enrolled"
	MfaOutcomeStepUpRequired = "mfa-step-up-required"
	MfaOutcomeBadRequest     = "mfa-bad-request"
	MfaOutcomeForbidden      = "mfa-forbidden"
	MfaOutcomeUnauthorized   = "mfa-unauthorized"
)

// MfaError is a refusal of a second factor, with the outcome that a client can act on
type MfaError struct {
	Outcome string
	Err     error
}

func (e *MfaError) Error() string {
	return e.Err.Error()
}

func (e *MfaError) Unwrap() error {
	return e.Err
}

func newMfaError(outcome string, err error) error {
	return &MfaError{Outcome: outcome, Err: err}
}

// NewMfaError is a refusal with an outcome, for the controllers
func NewMfaError(outcome string, msg string) error {
	return newMfaError(outcome, errors.New(msg))
}

// GetMfaOutcome returns the outcome of a refusal of a second factor, "" for any other error
func GetMfaOutcome(err error) string {
	var mfaErr *MfaError
	if errors.As(err, &mfaErr) {
		return mfaErr.Outcome
	}
	return ""
}

// mfaStepUpNow is replaced by the tests, the codes depend on the clock
var mfaStepUpNow = time.Now

// the factors that a step-up check takes: a push can be approved by whoever asked for it, and a RADIUS code is
// checked by a server that may accept it twice
var mfaStepUpTypes = []string{TotpType, EmailType, SmsType}

// MfaStepUpCheck is a request to verify a factor that the user enrolled, outside a sign-in
type MfaStepUpCheck struct {
	MfaType      string
	Passcode     string
	RecoveryCode string
	ClientIp     string
	Lang         string
}

// GetEnrolledMfaProps returns the factor as stored in the user, there is no other source
// of the secret or the destination, and no fallback to another factor
func GetEnrolledMfaProps(user *User, mfaType string) (*MfaProps, error) {
	if !util.InSlice(mfaStepUpTypes, mfaType) {
		return nil, NewMfaError(MfaOutcomeBadRequest, "Invalid multi-factor authentication type")
	}

	mfaProps := user.GetMfaProps(mfaType, false)
	if !mfaProps.Enabled {
		return nil, newMfaError(MfaOutcomeNotEnrolled, fmt.Errorf("the user has not enrolled the multi-factor authentication type: %s", mfaType))
	}

	if mfaType == SmsType {
		mfaProps.CountryCode = user.GetCountryCode(user.CountryCode)
	}
	return mfaProps, nil
}

// VerifyEnrolledMfa checks a passcode or a recovery code against the factor that the user enrolled.
// Unlike the sign-in, the organization's master verification code is not accepted, and the MFA remember
// period does not apply. A passcode works once, here and at the sign-in alike.
func VerifyEnrolledMfa(user *User, check *MfaStepUpCheck) error {
	if check.RecoveryCode != "" && check.Passcode != "" {
		return NewMfaError(MfaOutcomeBadRequest, "send either a passcode or a recovery code, not both")
	}
	if len(check.Passcode) > maxMfaPasscodeLength || len(check.RecoveryCode) > maxMfaPasscodeLength {
		return NewMfaError(MfaOutcomeBadRequest, "the passcode is too long")
	}

	if check.RecoveryCode != "" {
		if !user.IsMfaEnabled() {
			return NewMfaError(MfaOutcomeNotEnrolled, "the user has not enrolled any multi-factor authentication")
		}
		return verifyMfaWithIpLimit(user, check, func() error { return MfaRecover(user, check.RecoveryCode) })
	}

	if check.Passcode == "" {
		return NewMfaError(MfaOutcomeBadRequest, "missing passcode or recovery code")
	}

	mfaProps, err := GetEnrolledMfaProps(user, check.MfaType)
	if err != nil {
		return err
	}

	if check.MfaType == TotpType {
		return verifyMfaWithIpLimit(user, check, func() error { return verifyTotpOnce(user, mfaProps, check.Passcode, mfaStepUpNow()) })
	}

	mfaUtil := GetMfaUtil(check.MfaType, mfaProps)
	if mfaUtil == nil {
		return NewMfaError(MfaOutcomeBadRequest, "Invalid multi-factor authentication type")
	}
	return verifyMfaWithIpLimit(user, check, func() error { return mfaUtil.Verify(check.Passcode, check.Lang) })
}

// verifyMfaWithIpLimit adds a limit per client address and user to the per-user limit of the sign-in, which
// counts every failure, whichever endpoint it came from
func verifyMfaWithIpLimit(user *User, check *MfaStepUpCheck, verify func() error) error {
	var extra []mfaLimit
	if check.ClientIp != "" {
		extra = append(extra, getMfaStepUpIpLimit(user, check.ClientIp))
	}
	return verifyMfaWithLimits(user, extra, verify, true, check.Lang)
}

// VerifyUserMfaPasscode checks a passcode of a factor that the user enrolled, for the sign-in and the RADIUS
// server: a TOTP code works once, whichever check sees it first, the step-up check included, and a push only
// when it was approved for this user's sign-in
func VerifyUserMfaPasscode(user *User, mfaUtil MfaInterface, passcode string, lang string) error {
	switch mfa := mfaUtil.(type) {
	case *TotpMfa:
		return verifyTotpOnce(user, mfa.MfaProps, passcode, mfaStepUpNow())
	case *PushMfa:
		return mfa.verifyForUser(user.GetId(), passcode, PushPurposeSignin)
	}
	return mfaUtil.Verify(passcode, lang)
}

func verifyTotpOnce(user *User, mfaProps *MfaProps, passcode string, now time.Time) error {
	if mfaProps == nil || mfaProps.Secret == "" {
		return NewMfaError(MfaOutcomeNotEnrolled, "totp is not enabled")
	}

	stepTime, ok := matchTotpCode(mfaProps.Secret, passcode, now)
	if !ok {
		return NewMfaError(MfaOutcomeWrongCode, "totp passcode error")
	}

	claimed, err := claimTotpTime(user, stepTime)
	if err != nil {
		return err
	}
	if !claimed {
		return NewMfaError(MfaOutcomeWrongCode, "the totp passcode has already been used")
	}
	return nil
}

// matchTotpCode returns the start, in Unix seconds, of the time step that the passcode was generated for. One
// step of clock skew in either direction is accepted as in the sign-in.
func matchTotpCode(storedSecret string, passcode string, now time.Time) (int64, bool) {
	// an imported hardware token may have another time step or length, kept after its secret, see otp_token.go
	secret, period, digits := parseTotpSecret(storedSecret)
	passcode = strings.TrimSpace(passcode)
	if period == 0 || len(passcode) != digits.Length() {
		return 0, false
	}

	opts := totp.ValidateOpts{Period: period, Digits: digits, Algorithm: otp.AlgorithmSHA1}
	currentStep := now.UTC().Unix() / int64(period)
	for _, step := range []int64{currentStep + 1, currentStep, currentStep - 1} {
		stepTime := step * int64(period)
		expected, err := totp.GenerateCodeCustom(secret, time.Unix(stepTime, 0).UTC(), opts)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(passcode)) == 1 {
			return stepTime, true
		}
	}
	return 0, false
}

// claimTotpTime stores the time step as the last accepted one when it starts later than the stored one. The
// comparison is in the UPDATE, so of two requests with the same code only one affects a row. The time is in
// seconds, not in steps, so a token with another period compares the same way.
func claimTotpTime(user *User, stepTime int64) (bool, error) {
	affected, err := ormer.Engine.Table(&User{}).
		Where("owner = ? AND name = ? AND (mfa_totp_last_time IS NULL OR mfa_totp_last_time < ?)", user.Owner, user.Name, stepTime).
		Update(map[string]interface{}{"mfa_totp_last_time": stepTime})
	if err != nil {
		return false, err
	}

	if affected == 0 {
		return false, nil
	}
	user.MfaTotpLastTime = stepTime
	return true, nil
}

// getMfaAmr returns the "amr" claim of the proof, with the RFC 8176 values where one exists
func getMfaAmr(mfaType string) []string {
	switch mfaType {
	case TotpType:
		return []string{"mfa", "otp"}
	case SmsType:
		return []string{"mfa", "sms"}
	default:
		return []string{"mfa"}
	}
}

// MfaProofClaims are the claims of the proof that a user passed a step-up check. The user is only "sub": a
// relying party that reads the owner and name of an access token finds none here.
type MfaProofClaims struct {
	TokenType string   `json:"tokenType"`
	Amr       []string `json:"amr"`
	MfaType   string   `json:"mfa_type"`
	AuthTime  int64    `json:"auth_time"`
	Action    string   `json:"action,omitempty"`
	Nonce     string   `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

// MfaProofSigner signs the proof of a step-up check. It is made before the check, so that a proof that can't
// be signed (an action or a nonce too long, no certificate) is refused before the code is used up.
type MfaProofSigner struct {
	application *Application
	user        *User
	action      string
	nonce       string
	issuer      string
	audience    string
	method      jwt.SigningMethod
	key         interface{}
	keyId       string
}

// NewMfaProofSigner prepares the proof for the application, with the key of the application. The relying
// party verifies it with the application's certificate, checks the "typ" header, and accepts each "jti" once.
// The token is not an access token: it is not in the token table.
func NewMfaProofSigner(application *Application, user *User, action string, nonce string, host string) (*MfaProofSigner, error) {
	if application == nil {
		return nil, NewMfaError(MfaOutcomeBadRequest, "the application of the check is not known")
	}
	if len(action) > maxMfaProofClaimSize || len(nonce) > maxMfaProofClaimSize {
		return nil, NewMfaError(MfaOutcomeBadRequest, "the action or the nonce is too long")
	}

	issuer, err := GetOidcIssuerByApplication(host, application)
	if err != nil {
		return nil, err
	}

	audience := application.ClientId
	if application.IsShared && !IsClientIdMetadataUrl(application.ClientId) {
		audience = application.ClientId + "-org-" + user.Owner
	}

	signingApplication := getSigningApplication(application, user.Owner)
	method := getJwtSigningMethod(signingApplication)
	cert, err := getCertByApplication(signingApplication)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, fmt.Errorf("The cert of the application \"%s\" does not exist", application.GetId())
	}

	key, err := getJwtSigningKey(method, cert)
	if err != nil {
		return nil, err
	}

	return &MfaProofSigner{
		application: application, user: user, action: action, nonce: nonce,
		issuer: issuer, audience: audience, method: method, key: key, keyId: cert.GetKeyId(),
	}, nil
}

// Sign signs the proof of a check of the factor at authTime
func (signer *MfaProofSigner) Sign(mfaType string, authTime time.Time) (string, error) {
	claims := MfaProofClaims{
		TokenType: "mfa-proof",
		Amr:       getMfaAmr(mfaType),
		MfaType:   mfaType,
		AuthTime:  authTime.Unix(),
		Action:    signer.action,
		Nonce:     signer.nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    signer.issuer,
			Subject:   signer.user.Id,
			Audience:  []string{signer.audience},
			ExpiresAt: jwt.NewNumericDate(authTime.Add(MfaProofLifetimeInSeconds * time.Second)),
			NotBefore: jwt.NewNumericDate(authTime),
			IssuedAt:  jwt.NewNumericDate(authTime),
			ID:        util.GetId(signer.application.Owner, util.GenerateId()),
		},
	}

	token := jwt.NewWithClaims(signer.method, claims)
	token.Header["kid"] = signer.keyId
	token.Header["typ"] = MfaProofTokenType
	return signJwtToken(token, signer.key)
}

// GenerateMfaProofToken signs the proof of a step-up check with the key of the application
func GenerateMfaProofToken(application *Application, user *User, mfaType string, action string, nonce string, authTime time.Time, host string) (string, error) {
	signer, err := NewMfaProofSigner(application, user, action, nonce, host)
	if err != nil {
		return "", err
	}
	return signer.Sign(mfaType, authTime)
}

// MfaStepUpDest is where a code of the enrolled factor goes, always read from the user
type MfaStepUpDest struct {
	Dest        string
	CountryCode string
}

// GetMfaStepUpDest returns the enrolled email address or phone number that a code is sent to
func GetMfaStepUpDest(user *User, mfaType string) (*MfaStepUpDest, error) {
	if mfaType != EmailType && mfaType != SmsType {
		return nil, NewMfaError(MfaOutcomeBadRequest, "Invalid multi-factor authentication type")
	}

	mfaProps, err := GetEnrolledMfaProps(user, mfaType)
	if err != nil {
		return nil, err
	}
	if mfaProps.Secret == "" {
		return nil, newMfaError(MfaOutcomeNotEnrolled, fmt.Errorf("the user has no destination for the multi-factor authentication type: %s", mfaType))
	}

	dest := &MfaStepUpDest{Dest: mfaProps.Secret, CountryCode: mfaProps.CountryCode}
	if mfaType == SmsType {
		phone, ok := util.GetE164Number(mfaProps.Secret, mfaProps.CountryCode)
		if !ok {
			return nil, newMfaError(MfaOutcomeNotEnrolled, fmt.Errorf("the phone number of the user is invalid in the region %s", mfaProps.CountryCode))
		}
		dest.Dest = phone
	}
	return dest, nil
}

// SendMfaStepUpCode sends a code to the email address or the phone number that the user enrolled
func SendMfaStepUpCode(application *Application, user *User, mfaType string, clientIp string, host string, lang string) error {
	dest, err := GetMfaStepUpDest(user, mfaType)
	if err != nil {
		return err
	}

	organization, err := GetOrganizationByUser(user)
	if err != nil {
		return err
	}
	if organization == nil {
		return errors.New(i18n.Translate(lang, "check:Organization does not exist"))
	}

	// the sign-in uses the same method of the application's provider rules
	const method = "mfaAuth"
	var provider *Provider
	if mfaType == EmailType {
		provider, err = application.GetEmailProvider(method)
	} else {
		provider, err = application.GetSmsProvider(method, dest.CountryCode)
	}
	if err != nil {
		return err
	}
	if provider == nil {
		kind := "an Email"
		if mfaType == SmsType {
			kind = "a SMS"
		}
		return fmt.Errorf("please add %s provider to the \"Providers\" list for the application: %s", kind, application.Name)
	}

	if err = IsAllowSend(user, clientIp, provider.Category, application, lang); err != nil {
		return newMfaError(MfaOutcomeRateLimited, err)
	}

	if mfaType == EmailType {
		return SendVerificationCodeToEmail(organization, user, provider, clientIp, dest.Dest, method, host, application.Name, application, lang)
	}
	return SendVerificationCodeToPhone(organization, user, provider, clientIp, dest.Dest, application, lang)
}

// AddMfaStepUpRecord writes the audit record of a step-up check or of a code sent for it, passed or failed
func AddMfaStepUpRecord(action string, user *User, application *Application, mfaType string, caller string, clientIp string, lang string, checkErr error) {
	applicationName := ""
	if application != nil {
		applicationName = application.GetId()
	}

	result, status, msg := "passed", "ok", ""
	if checkErr != nil {
		result, status, msg = "failed", "error", checkErr.Error()
	}

	record := &Record{
		Name:         util.GenerateId(),
		CreatedTime:  util.GetCurrentTime(),
		Organization: user.Owner,
		ClientIp:     clientIp,
		User:         user.Name,
		Method:       "POST",
		RequestUri:   "/api/" + action,
		Action:       action,
		Language:     lang,
		Object: util.StructToJson(map[string]string{
			"user":        user.GetId(),
			"application": applicationName,
			"mfaType":     mfaType,
			"caller":      caller,
			"result":      result,
		}),
		Response:   fmt.Sprintf("{status:\"%s\", msg:\"%s\"}", status, msg),
		StatusCode: 200,
		Detail:     result,
	}
	AddRecord(record)
}
