// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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
	"encoding/json"
	"errors"

	"github.com/casdoor/casdoor/util"
)

type MfaProps struct {
	Enabled            bool     `json:"enabled"`
	IsPreferred        bool     `json:"isPreferred"`
	MfaType            string   `json:"mfaType" form:"mfaType"`
	Secret             string   `json:"secret,omitempty"`
	CountryCode        string   `json:"countryCode,omitempty"`
	URL                string   `json:"url,omitempty"`
	RecoveryCodes      []string `json:"recoveryCodes,omitempty"`
	MfaRememberInHours int      `json:"mfaRememberInHours"`
}

type MfaInterface interface {
	Initiate(userId string, issuer string) (*MfaProps, error)
	SetupVerify(passcode string, lang string) error
	Enable(user *User) error
	Verify(passcode string, lang string) error
}

const (
	EmailType  = "email"
	SmsType    = "sms"
	TotpType   = "app"
	RadiusType = "radius"
	PushType   = "push"
)

const (
	MfaSessionUserId = "MfaSessionUserId"
	NextMfa          = "NextMfa"
	RequiredMfa      = "RequiredMfa"
)

func GetMfaUtil(mfaType string, config *MfaProps) MfaInterface {
	switch mfaType {
	case SmsType:
		return NewSmsMfaUtil(config)
	case EmailType:
		return NewEmailMfaUtil(config)
	case TotpType:
		return NewTotpMfaUtil(config)
	case RadiusType:
		return NewRadiusMfaUtil(config)
	case PushType:
		return NewPushMfaUtil(config)
	}

	return nil
}

// VerifyMfaWithLimit checks a factor of the user against the per-user MFA limit, which the sign-in, the step-up
// check and the setup share: the try is reserved in the database before the factor is checked, so concurrent
// tries and the replicas of Casdoor count the same tries. A pass forgets the earlier failures.
func VerifyMfaWithLimit(user *User, verify func() error, lang string) error {
	return verifyMfaWithLimits(user, nil, verify, true, lang)
}

// VerifyMfaSetupWithLimit checks a code of a factor being set up against the same limit. A pass shows a code of
// the new factor, not of the one the user has, so it takes only its own try back and forgets no failure.
func VerifyMfaSetupWithLimit(user *User, verify func() error, lang string) error {
	return verifyMfaWithLimits(user, nil, verify, false, lang)
}

// SetupVerifyForUser checks the code of a factor that the user is setting up: a push only when it was approved
// for this user's setup
func SetupVerifyForUser(user *User, mfaUtil MfaInterface, passcode string, lang string) error {
	if mfa, ok := mfaUtil.(*PushMfa); ok {
		return mfa.verifyForUser(user.GetId(), passcode, PushPurposeSetup)
	}
	return mfaUtil.SetupVerify(passcode, lang)
}

// maxRecoveryCodeTries bounds the retries of a recovery code whose list another check changed meanwhile
const maxRecoveryCodeTries = 5

// MfaRecover uses a recovery code of the user. The codes are read from the database, not from the user given,
// which may have been loaded before another request used one, and are written back only if they did not change
// since: of two checks of one code only one passes, and no stale copy brings a used code back.
func MfaRecover(user *User, recoveryCode string) error {
	for i := 0; i < maxRecoveryCodeTries; i++ {
		var stored string
		has, err := ormer.Engine.Table(&User{}).Where("owner = ? AND name = ?", user.Owner, user.Name).Cols("recovery_codes").Get(&stored)
		if err != nil {
			return err
		}
		if !has {
			return errors.New("the user doesn't exist")
		}

		codes := []string{}
		if stored != "" && stored != "null" {
			if err = json.Unmarshal([]byte(stored), &codes); err != nil {
				return err
			}
		}
		if len(codes) == 0 {
			return NewMfaError(MfaOutcomeWrongCode, "do not have recovery codes")
		}

		rest, hit := removeRecoveryCode(codes, recoveryCode)
		if !hit {
			return NewMfaError(MfaOutcomeWrongCode, "recovery code not found")
		}

		value, err := json.Marshal(rest)
		if err != nil {
			return err
		}
		affected, err := ormer.Engine.Table(&User{}).Where("owner = ? AND name = ? AND recovery_codes = ?", user.Owner, user.Name, stored).
			Update(map[string]interface{}{"recovery_codes": string(value)})
		if err != nil {
			return err
		}
		if affected == 1 {
			user.RecoveryCodes = rest
			return nil
		}
		// another request changed the codes after they were read: read them again
	}
	return errors.New("the recovery codes are being changed, please try again")
}

// removeRecoveryCode returns the codes without the given one, compared in constant time
func removeRecoveryCode(codes []string, recoveryCode string) ([]string, bool) {
	rest := make([]string, 0, len(codes))
	hit := false
	for _, code := range codes {
		if !hit && recoveryCode != "" && subtle.ConstantTimeCompare([]byte(code), []byte(recoveryCode)) == 1 {
			hit = true
			continue
		}
		rest = append(rest, code)
	}
	return rest, hit
}

func GetAllMfaProps(user *User, masked bool) []*MfaProps {
	mfaProps := []*MfaProps{}

	for _, mfaType := range []string{SmsType, EmailType, TotpType, RadiusType, PushType} {
		mfaProps = append(mfaProps, user.GetMfaProps(mfaType, masked))
	}
	return mfaProps
}

func (user *User) GetMfaProps(mfaType string, masked bool) *MfaProps {
	mfaProps := &MfaProps{}

	if mfaType == SmsType {
		if !user.MfaPhoneEnabled {
			return &MfaProps{
				Enabled: false,
				MfaType: mfaType,
			}
		}

		mfaProps = &MfaProps{
			Enabled:     user.MfaPhoneEnabled,
			MfaType:     mfaType,
			CountryCode: user.CountryCode,
		}
		if masked {
			mfaProps.Secret = util.GetMaskedPhone(user.Phone)
		} else {
			mfaProps.Secret = user.Phone
		}
	} else if mfaType == EmailType {
		if !user.MfaEmailEnabled {
			return &MfaProps{
				Enabled: false,
				MfaType: mfaType,
			}
		}

		mfaProps = &MfaProps{
			Enabled: user.MfaEmailEnabled,
			MfaType: mfaType,
		}
		if masked {
			mfaProps.Secret = util.GetMaskedEmail(user.Email)
		} else {
			mfaProps.Secret = user.Email
		}
	} else if mfaType == TotpType {
		if user.TotpSecret == "" {
			return &MfaProps{
				Enabled: false,
				MfaType: mfaType,
			}
		}

		mfaProps = &MfaProps{
			Enabled: true,
			MfaType: mfaType,
		}
		if masked {
			mfaProps.Secret = ""
		} else {
			mfaProps.Secret = user.TotpSecret
		}
	} else if mfaType == RadiusType {
		if !user.MfaRadiusEnabled {
			return &MfaProps{
				Enabled: false,
				MfaType: mfaType,
			}
		}

		mfaProps = &MfaProps{
			Enabled: user.MfaRadiusEnabled,
			MfaType: mfaType,
		}
		if masked {
			mfaProps.Secret = util.GetMaskedEmail(user.MfaRadiusUsername)
		} else {
			mfaProps.Secret = user.MfaRadiusUsername
		}
		mfaProps.URL = user.MfaRadiusProvider
	} else if mfaType == PushType {
		if !user.MfaPushEnabled {
			return &MfaProps{
				Enabled: false,
				MfaType: mfaType,
			}
		}

		mfaProps = &MfaProps{
			Enabled: user.MfaPushEnabled,
			MfaType: mfaType,
		}
		if masked {
			mfaProps.Secret = util.GetMaskedEmail(user.MfaPushReceiver)
		} else {
			mfaProps.Secret = user.MfaPushReceiver
		}
		mfaProps.URL = user.MfaPushProvider
	}

	if user.PreferredMfaType == mfaType {
		mfaProps.IsPreferred = true
	}
	return mfaProps
}

func DisabledMultiFactorAuth(user *User) error {
	user.PreferredMfaType = ""
	user.RecoveryCodes = []string{}
	user.MfaPhoneEnabled = false
	user.MfaEmailEnabled = false
	user.TotpSecret = ""
	user.MfaRadiusEnabled = false
	user.MfaRadiusUsername = ""
	user.MfaRadiusProvider = ""
	user.MfaPushEnabled = false
	user.MfaPushReceiver = ""
	user.MfaPushProvider = ""
	// a new TOTP secret starts without a used code
	user.MfaTotpLastTime = 0

	_, err := updateUser(user.GetId(), user, []string{"preferred_mfa_type", "recovery_codes", "mfa_phone_enabled", "mfa_email_enabled", "totp_secret", "mfa_totp_last_time", "mfa_radius_enabled", "mfa_radius_username", "mfa_radius_provider", "mfa_push_enabled", "mfa_push_receiver", "mfa_push_provider"})
	if err != nil {
		return err
	}
	return nil
}

func SetPreferredMultiFactorAuth(user *User, mfaType string) error {
	user.PreferredMfaType = mfaType

	_, err := UpdateUser(user.GetId(), user, []string{"preferred_mfa_type"}, false)
	if err != nil {
		return err
	}
	return nil
}
