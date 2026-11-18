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
	"sync"
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

const (
	maxMfaPasscodeLength = 256
	maxMfaProofClaimSize = 256
)

// mfaStepUpNow is replaced by the tests, the codes depend on the clock
var mfaStepUpNow = time.Now

var mfaStepUpTypes = []string{TotpType, EmailType, SmsType, PushType, RadiusType}

// the codes and recovery codes are consumed by a read followed by a write, so two checks
// of the same code must not interleave
var (
	mfaCodeLock     sync.Mutex
	mfaRecoveryLock sync.Mutex
)

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
		return nil, errors.New("Invalid multi-factor authentication type")
	}

	mfaProps := user.GetMfaProps(mfaType, false)
	if !mfaProps.Enabled {
		return nil, fmt.Errorf("the user has not enrolled the multi-factor authentication type: %s", mfaType)
	}

	if mfaType == SmsType {
		mfaProps.CountryCode = user.GetCountryCode(user.CountryCode)
	}
	return mfaProps, nil
}

// VerifyEnrolledMfa checks a passcode or a recovery code against the factor that the user enrolled.
// Unlike the sign-in, the organization's master verification code is not accepted, a passcode
// is never accepted twice, and the MFA remember period does not apply.
func VerifyEnrolledMfa(user *User, check *MfaStepUpCheck) error {
	if check.RecoveryCode != "" && check.Passcode != "" {
		return errors.New("send either a passcode or a recovery code, not both")
	}
	if len(check.Passcode) > maxMfaPasscodeLength || len(check.RecoveryCode) > maxMfaPasscodeLength {
		return errors.New("the passcode is too long")
	}

	if check.RecoveryCode != "" {
		if !user.IsMfaEnabled() {
			return errors.New("the user has not enrolled any multi-factor authentication")
		}
		return verifyMfaWithIpLimit(user, check, func() error { return verifyRecoveryCodeOnce(user, check.RecoveryCode) })
	}

	if check.Passcode == "" {
		return errors.New("missing passcode or recovery code")
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
		return errors.New("Invalid multi-factor authentication type")
	}

	verify := func() error { return mfaUtil.Verify(check.Passcode, check.Lang) }
	if check.MfaType == EmailType || check.MfaType == SmsType {
		verify = func() error {
			mfaCodeLock.Lock()
			defer mfaCodeLock.Unlock()
			return mfaUtil.Verify(check.Passcode, check.Lang)
		}
	}
	return verifyMfaWithIpLimit(user, check, verify)
}

func getMfaStepUpIpKey(user *User) string {
	return "mfa-step-up:" + user.GetId()
}

// verifyMfaWithIpLimit adds a limit per client address and user to the per-user limit of the sign-in,
// the same user limit as the sign-in counts every failure, whichever endpoint it came from
func verifyMfaWithIpLimit(user *User, check *MfaStepUpCheck, verify func() error) error {
	ipKey := getMfaStepUpIpKey(user)
	if err := checkVerifyCodeIpErrorTimes(check.ClientIp, ipKey, check.Lang); err != nil {
		return err
	}

	err := VerifyMfaWithLimit(user, verify, check.Lang)
	if err != nil {
		_ = recordVerifyCodeIpErrorInfo(check.ClientIp, ipKey, check.Lang)
		return err
	}

	resetVerifyCodeIpErrorTimes(check.ClientIp, ipKey)
	return nil
}

func verifyRecoveryCodeOnce(user *User, recoveryCode string) error {
	mfaRecoveryLock.Lock()
	defer mfaRecoveryLock.Unlock()

	// the codes are read again under the lock, a concurrent check may have used this one
	fresh, err := getUser(user.Owner, user.Name)
	if err != nil {
		return err
	}
	if fresh == nil {
		return errors.New("the user doesn't exist")
	}

	return MfaRecover(fresh, recoveryCode)
}

func verifyTotpOnce(user *User, mfaProps *MfaProps, passcode string, now time.Time) error {
	step, ok := matchTotpStep(mfaProps.Secret, passcode, now)
	if !ok {
		return errors.New("totp passcode error")
	}

	claimed, err := claimTotpStep(user, step)
	if err != nil {
		return err
	}
	if !claimed {
		return errors.New("the totp passcode has already been used")
	}
	return nil
}

// matchTotpStep returns the time step that the passcode was generated for, one step
// of clock skew in either direction is accepted as in the sign-in
func matchTotpStep(storedSecret string, passcode string, now time.Time) (int64, bool) {
	// an imported hardware token may have another time step or length, kept after its secret, see otp_token.go
	secret, period, digits := parseTotpSecret(storedSecret)
	passcode = strings.TrimSpace(passcode)
	if period == 0 || len(passcode) != digits.Length() {
		return 0, false
	}

	opts := totp.ValidateOpts{Period: period, Digits: digits, Algorithm: otp.AlgorithmSHA1}
	currentStep := now.UTC().Unix() / int64(period)
	for _, step := range []int64{currentStep + 1, currentStep, currentStep - 1} {
		expected, err := totp.GenerateCodeCustom(secret, time.Unix(step*int64(period), 0).UTC(), opts)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(passcode)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// claimTotpStep stores the step as the last accepted one when it is later than the stored one. The
// comparison is in the UPDATE, so of two requests with the same code only one affects a row.
func claimTotpStep(user *User, step int64) (bool, error) {
	affected, err := ormer.Engine.Table(&User{}).
		Where("owner = ? AND name = ? AND (mfa_totp_last_step IS NULL OR mfa_totp_last_step < ?)", user.Owner, user.Name, step).
		Update(map[string]interface{}{"mfa_totp_last_step": step})
	if err != nil {
		return false, err
	}

	if affected == 0 {
		return false, nil
	}
	user.MfaTotpLastStep = step
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

// MfaProofClaims are the claims of the proof that a user passed a step-up check
type MfaProofClaims struct {
	TokenType string   `json:"tokenType"`
	Owner     string   `json:"owner"`
	Name      string   `json:"name"`
	Amr       []string `json:"amr"`
	MfaType   string   `json:"mfa_type"`
	AuthTime  int64    `json:"auth_time"`
	Action    string   `json:"action,omitempty"`
	Nonce     string   `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

// GenerateMfaProofToken signs the proof of a step-up check with the key of the application, the
// relying party verifies it with the application's certificate like any other token, and accepts
// each "jti" once. The token is not an access token: it is not in the token table.
func GenerateMfaProofToken(application *Application, user *User, mfaType string, action string, nonce string, authTime time.Time, host string) (string, error) {
	if application == nil {
		return "", errors.New("the application of the check is not known")
	}
	if len(action) > maxMfaProofClaimSize || len(nonce) > maxMfaProofClaimSize {
		return "", errors.New("the action or the nonce is too long")
	}

	issuer, err := GetOidcIssuerByApplication(host, application)
	if err != nil {
		return "", err
	}

	audience := application.ClientId
	if application.IsShared && !IsClientIdMetadataUrl(application.ClientId) {
		audience = application.ClientId + "-org-" + user.Owner
	}

	claims := MfaProofClaims{
		TokenType: "mfa-proof",
		Owner:     user.Owner,
		Name:      user.Name,
		Amr:       getMfaAmr(mfaType),
		MfaType:   mfaType,
		AuthTime:  authTime.Unix(),
		Action:    action,
		Nonce:     nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   user.Id,
			Audience:  []string{audience},
			ExpiresAt: jwt.NewNumericDate(authTime.Add(MfaProofLifetimeInSeconds * time.Second)),
			NotBefore: jwt.NewNumericDate(authTime),
			IssuedAt:  jwt.NewNumericDate(authTime),
			ID:        util.GetId(application.Owner, util.GenerateId()),
		},
	}

	signingApplication := getSigningApplication(application, user.Owner)
	jwtMethod := getJwtSigningMethod(signingApplication)
	cert, err := getCertByApplication(signingApplication)
	if err != nil {
		return "", err
	}
	if cert == nil {
		return "", fmt.Errorf("The cert of the application \"%s\" does not exist", application.GetId())
	}

	key, err := getJwtSigningKey(jwtMethod, cert)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwtMethod, claims)
	token.Header["kid"] = cert.GetKeyId()
	return signJwtToken(token, key)
}

// MfaStepUpDest is where a code of the enrolled factor goes, always read from the user
type MfaStepUpDest struct {
	Dest        string
	CountryCode string
}

// GetMfaStepUpDest returns the enrolled email address or phone number that a code is sent to
func GetMfaStepUpDest(user *User, mfaType string) (*MfaStepUpDest, error) {
	if mfaType != EmailType && mfaType != SmsType {
		return nil, errors.New("Invalid multi-factor authentication type")
	}

	mfaProps, err := GetEnrolledMfaProps(user, mfaType)
	if err != nil {
		return nil, err
	}
	if mfaProps.Secret == "" {
		return nil, fmt.Errorf("the user has no destination for the multi-factor authentication type: %s", mfaType)
	}

	dest := &MfaStepUpDest{Dest: mfaProps.Secret, CountryCode: mfaProps.CountryCode}
	if mfaType == SmsType {
		phone, ok := util.GetE164Number(mfaProps.Secret, mfaProps.CountryCode)
		if !ok {
			return nil, fmt.Errorf("the phone number of the user is invalid in the region %s", mfaProps.CountryCode)
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
	if mfaType == EmailType {
		provider, err := application.GetEmailProvider(method)
		if err != nil {
			return err
		}
		if provider == nil {
			return fmt.Errorf("please add an Email provider to the \"Providers\" list for the application: %s", application.Name)
		}
		return SendVerificationCodeToEmail(organization, user, provider, clientIp, dest.Dest, method, host, application.Name, application, lang)
	}

	provider, err := application.GetSmsProvider(method, dest.CountryCode)
	if err != nil {
		return err
	}
	if provider == nil {
		return fmt.Errorf("please add a SMS provider to the \"Providers\" list for the application: %s", application.Name)
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
