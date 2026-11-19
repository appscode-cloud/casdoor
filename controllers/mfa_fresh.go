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

package controllers

import (
	"strings"
	"time"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// A user who has a second factor shows one again before a factor is set up, replaced or removed through the
// user's own session or access token: a stolen session must not swap in the thief's authenticator, nor remove
// the factor that a step-up check asks for. A passed check is kept in the session for mfaFreshTimeout: the
// step-up check (/api/mfa/verify) and the MFA step of the sign-in both keep it. A request may carry the check
// instead (stepUpMfaType and stepUpPasscode, or stepUpRecoveryCode), which a caller without a session, such as
// an access token, has to. An application with its client credentials, and an administrator changing another
// user, are not asked: they check the user themselves.
//
// The setup of a factor through the user's own session is kept in the session as well: the TOTP secret and the
// recovery code that /api/mfa/setup/initiate made are the ones /api/mfa/setup/enable turns on, and only once
// /api/mfa/setup/verify passed a code of that very secret or destination. The request can't name its own.

const (
	mfaFreshSession = "mfaFreshFactor"
	mfaFreshTimeout = 5 * time.Minute

	mfaSetupSession = "mfaSetupState"
	mfaSetupTimeout = 15 * time.Minute
)

type mfaFreshFactor struct {
	UserId string `json:"userId"`
	Time   int64  `json:"time"`
}

// mfaSetupState is a setup of a factor that the user began in this session
type mfaSetupState struct {
	UserId       string `json:"userId"`
	MfaType      string `json:"mfaType"`
	Secret       string `json:"secret,omitempty"`
	RecoveryCode string `json:"recoveryCode"`
	// a fresh factor was shown when the setup began, for a user who had one
	Fresh bool `json:"fresh"`
	// what setup/verify passed a code of, see getMfaSetupFingerprint
	Verified    string `json:"verified,omitempty"`
	CreatedTime int64  `json:"createdTime"`
}

// setMfaFresh keeps in the session that the user passed a second factor now
func (c *ApiController) setMfaFresh(userId string) {
	c.SetSession(mfaFreshSession, util.StructToJson(&mfaFreshFactor{UserId: userId, Time: time.Now().Unix()}))
}

// isMfaFresh reports whether the user passed a second factor in this session within mfaFreshTimeout
func (c *ApiController) isMfaFresh(userId string) bool {
	value, _ := c.GetSession(mfaFreshSession).(string)
	return isMfaFreshValue(value, userId, time.Now())
}

func isMfaFreshValue(value string, userId string, now time.Time) bool {
	if value == "" || userId == "" {
		return false
	}

	fresh := &mfaFreshFactor{}
	if err := util.JsonToStruct(value, fresh); err != nil {
		return false
	}
	passed := time.Unix(fresh.Time, 0)
	return fresh.UserId == userId && !passed.After(now) && now.Sub(passed) <= mfaFreshTimeout
}

// isMfaSelfService reports whether the request changes the factors of the user through the user's own session or
// token, not through an application's client credentials nor an administrator changing another user
func (c *ApiController) isMfaSelfService(user *object.User) bool {
	callerId := c.GetSessionUsername()
	return isMfaSelfServiceCaller(callerId, user.GetId(), callerId != user.GetId() && c.IsAdminOf(user))
}

func isMfaSelfServiceCaller(callerId string, userId string, isAdminOfAnother bool) bool {
	if strings.HasPrefix(callerId, "app/") {
		return false
	}
	return callerId == userId || !isAdminOfAnother
}

// checkFreshMfa passes when the user has no second factor yet, passed one in this session within
// mfaFreshTimeout, or passes the one the request carries. Otherwise it answers mfa-step-up-required, or the
// refusal of the check, and returns false.
func (c *ApiController) checkFreshMfa(user *object.User) bool {
	if !user.IsMfaEnabled() || c.isMfaFresh(user.GetId()) {
		return true
	}

	form := c.Ctx.Request.Form
	check := &object.MfaStepUpCheck{
		MfaType:      form.Get("stepUpMfaType"),
		Passcode:     form.Get("stepUpPasscode"),
		RecoveryCode: form.Get("stepUpRecoveryCode"),
		ClientIp:     util.GetClientIpFromRequest(c.Ctx.Request),
		Lang:         c.GetAcceptLanguage(),
	}
	if check.Passcode == "" && check.RecoveryCode == "" {
		c.ResponseErrorWithCode(object.MfaOutcomeStepUpRequired, "please verify your multi-factor authentication first, the user has one enabled", object.MfaOutcomeStepUpRequired)
		return false
	}

	mfaType := check.MfaType
	if check.RecoveryCode != "" {
		mfaType = object.MfaRecoveryType
	}
	err := object.VerifyEnrolledMfa(user, check)
	c.addMfaStepUpRecord("mfa-verify", &mfaStepUpSubject{user: user, caller: c.GetSessionUsername()}, mfaType, err)
	if err != nil {
		c.responseMfaError(err)
		return false
	}

	c.setMfaFresh(user.GetId())
	return true
}

// responseMfaError answers a refusal of a second factor with its outcome in "data"
func (c *ApiController) responseMfaError(err error) {
	outcome := object.GetMfaOutcome(err)
	if outcome == "" {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseErrorWithCode(outcome, err.Error(), outcome)
}

func (c *ApiController) setMfaSetupState(state *mfaSetupState) {
	c.SetSession(mfaSetupSession, util.StructToJson(state))
}

// getMfaSetupState returns the setup of the factor that the user began in this session, nil when there is none
// or it is too old
func (c *ApiController) getMfaSetupState(user *object.User, mfaType string) *mfaSetupState {
	value, _ := c.GetSession(mfaSetupSession).(string)
	return parseMfaSetupState(value, user.GetId(), mfaType, time.Now())
}

func parseMfaSetupState(value string, userId string, mfaType string, now time.Time) *mfaSetupState {
	if value == "" || userId == "" {
		return nil
	}

	state := &mfaSetupState{}
	if err := util.JsonToStruct(value, state); err != nil {
		return nil
	}
	created := time.Unix(state.CreatedTime, 0)
	if state.UserId != userId || state.MfaType != mfaType || created.After(now) || now.Sub(created) > mfaSetupTimeout {
		return nil
	}
	return state
}

func (c *ApiController) clearMfaSetupState() {
	c.DelSession(mfaSetupSession)
}

// getMfaSetupFingerprint names what a code of the factor being set up proves: the TOTP secret, the address or
// phone, the RADIUS account or the push receiver with its provider
func getMfaSetupFingerprint(mfaType string, secret string, dest string, countryCode string) string {
	switch mfaType {
	case object.TotpType:
		return mfaType + ":" + secret
	case object.SmsType, object.EmailType:
		return getMfaSetupDest(mfaType, dest, countryCode)
	default:
		return mfaType + ":" + dest + "|" + secret
	}
}
