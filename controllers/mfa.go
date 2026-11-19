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

package controllers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// MfaSetupInitiate
// @Title MfaSetupInitiate
// @Tag MFA API
// @Description setup MFA. Through the user's own session or access token, a user who has a factor shows one first: within 5 minutes of passing /api/mfa/verify or the MFA step of the sign-in in the same session, or in the request with stepUpMfaType and stepUpPasscode, or stepUpRecoveryCode; else the answer is an error with the data mfa-step-up-required. An application with client credentials and an administrator of another user are not asked.
// @Param   mfaType formData string true "The type of MFA to set up (app/sms/email)"
// @Param   owner   formData string true "The owner of the user"
// @Param   name    formData string true "The name of the user"
// @Param   stepUpMfaType      formData string false "The type of a factor the user has, to show it with the request (app/sms/email)"
// @Param   stepUpPasscode     formData string false "A passcode of that factor"
// @Param   stepUpRecoveryCode formData string false "A recovery code, instead of the passcode"
// @Success 200 {object} controllers.Response The Response object
// @router /mfa/setup/initiate [post]
func (c *ApiController) MfaSetupInitiate() {
	owner := c.Ctx.Request.Form.Get("owner")
	name := c.Ctx.Request.Form.Get("name")
	mfaType := c.Ctx.Request.Form.Get("mfaType")
	userId := util.GetId(owner, name)

	if len(userId) == 0 {
		c.ResponseError(http.StatusText(http.StatusBadRequest))
		return
	}

	MfaUtil := object.GetMfaUtil(mfaType, nil)
	if MfaUtil == nil {
		c.ResponseError("Invalid auth type")
		return
	}

	user, err := object.GetUser(userId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if user == nil {
		c.ResponseError("User doesn't exist")
		return
	}

	organization, err := object.GetOrganizationByUser(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if !object.IsMfaTypeAllowed(organization, user, mfaType) {
		c.ResponseError(fmt.Sprintf("the MFA type: %s is not allowed by the MFA items", mfaType))
		return
	}

	// through the user's own session, a user who has a factor shows one before another is set up
	selfService := c.isMfaSelfService(user)
	fresh := false
	if selfService && user.IsMfaEnabled() {
		if !c.checkFreshMfa(user) {
			return
		}
		fresh = true
	}

	issuer := ""
	if organization != nil && organization.DisplayName != "" {
		issuer = organization.DisplayName
	} else if organization != nil {
		issuer = organization.Name
	}

	mfaProps, err := MfaUtil.Initiate(user.GetId(), issuer)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	recoveryCode := util.GenerateUUID()
	mfaProps.RecoveryCodes = []string{recoveryCode}
	mfaProps.MfaRememberInHours = organization.MfaRememberInHours

	// the secret and the recovery code that setup/enable turns on, for a setup through the user's own session
	if selfService {
		state := &mfaSetupState{UserId: user.GetId(), MfaType: mfaType, RecoveryCode: recoveryCode, Fresh: fresh, CreatedTime: time.Now().Unix()}
		if mfaType == object.TotpType {
			state.Secret = mfaProps.Secret
		}
		c.setMfaSetupState(state)
	}

	resp := mfaProps
	c.ResponseOk(resp)
}

// MfaSetupVerify
// @Title MfaSetupVerify
// @Tag MFA API
// @Description setup verify totp
// @Param   secret   formData string true "The MFA secret"
// @Param   passcode formData string true "The MFA passcode"
// @Success 200 {object} controllers.Response The Response object
// @router /mfa/setup/verify [post]
func (c *ApiController) MfaSetupVerify() {
	mfaType := c.Ctx.Request.Form.Get("mfaType")
	passcode := c.Ctx.Request.Form.Get("passcode")
	secret := c.Ctx.Request.Form.Get("secret")
	dest := c.Ctx.Request.Form.Get("dest")
	countryCode := c.Ctx.Request.Form.Get("countryCode")

	if mfaType == "" || passcode == "" {
		c.ResponseError("missing auth type or passcode")
		return
	}

	user, err := object.GetUser(util.GetId(c.Ctx.Request.Form.Get("owner"), c.Ctx.Request.Form.Get("name")))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError("User doesn't exist")
		return
	}

	// through the user's own session, the TOTP secret is the one that setup/initiate made in this session
	var state *mfaSetupState
	if c.isMfaSelfService(user) {
		state = c.getMfaSetupState(user, mfaType)
		if state == nil {
			c.ResponseErrorWithCode(object.MfaOutcomeBadRequest, "the MFA setup has expired or was not started in this session, please start it again", object.MfaOutcomeBadRequest)
			return
		}
		if mfaType == object.TotpType {
			if secret != "" && secret != state.Secret {
				c.ResponseErrorWithCode(object.MfaOutcomeBadRequest, "the totp secret is not the one of the MFA setup", object.MfaOutcomeBadRequest)
				return
			}
			secret = state.Secret
		}
	}

	config := &object.MfaProps{
		MfaType: mfaType,
	}
	if mfaType == object.TotpType {
		if secret == "" {
			c.ResponseError("totp secret is missing")
			return
		}
		config.Secret = secret
	} else if mfaType == object.SmsType {
		if dest == "" {
			c.ResponseError("destination is missing")
			return
		}
		config.Secret = dest
		if countryCode == "" {
			c.ResponseError("country code is missing")
			return
		}
		config.CountryCode = countryCode
	} else if mfaType == object.EmailType {
		if dest == "" {
			c.ResponseError("destination is missing")
			return
		}
		config.Secret = dest
	} else if mfaType == object.RadiusType {
		if dest == "" {
			c.ResponseError("RADIUS username is missing")
			return
		}
		config.Secret = dest
		if secret == "" {
			c.ResponseError("RADIUS provider is missing")
			return
		}
		config.URL = secret
	} else if mfaType == object.PushType {
		if dest == "" {
			c.ResponseError("push notification receiver is missing")
			return
		}
		config.Secret = dest
		if secret == "" {
			c.ResponseError("push notification provider is missing")
			return
		}
		config.URL = secret
	}

	mfaUtil := object.GetMfaUtil(mfaType, config)
	if mfaUtil == nil {
		c.ResponseError("Invalid multi-factor authentication type")
		return
	}

	verifiedDest := getMfaSetupDest(mfaType, dest, countryCode)
	err = object.VerifyMfaSetupWithLimit(user, func() error { return object.SetupVerifyForUser(user, mfaUtil, passcode, c.GetAcceptLanguage()) }, c.GetAcceptLanguage())
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.SetSession(mfaSetupVerifiedDestSession, verifiedDest)
	if state != nil {
		state.Verified = getMfaSetupFingerprint(mfaType, secret, dest, countryCode)
		c.setMfaSetupState(state)
	}
	c.ResponseOk(http.StatusText(http.StatusOK))
}

const mfaSetupVerifiedDestSession = "mfaSetupVerifiedDest"

func getMfaSetupDest(mfaType string, dest string, countryCode string) string {
	if mfaType == object.SmsType {
		dest, _ = util.GetE164Number(dest, countryCode)
	}
	return mfaType + ":" + dest
}

func (c *ApiController) checkMfaSetupDest(user *object.User, mfaType string) bool {
	if (mfaType != object.SmsType && mfaType != object.EmailType) || c.IsAdminOf(user) {
		return true
	}

	dest := user.Email
	if mfaType == object.SmsType {
		dest = user.Phone
	}
	if c.GetSession(mfaSetupVerifiedDestSession) != getMfaSetupDest(mfaType, dest, user.CountryCode) {
		c.ResponseError("the MFA destination has not been verified")
		return false
	}
	return true
}

// MfaSetupEnable
// @Title MfaSetupEnable
// @Tag MFA API
// @Description enable totp. Through the user's own session or access token, a user who has a factor shows one first: within 5 minutes of passing /api/mfa/verify or the MFA step of the sign-in in the same session, or in the request with stepUpMfaType and stepUpPasscode, or stepUpRecoveryCode; else the answer is an error with the data mfa-step-up-required. An application with client credentials and an administrator of another user are not asked. Through the user's own session, it turns on the TOTP secret and the recovery code that setup/initiate made in that session, once setup/verify passed a code of it.
// @Param   owner   formData string true "The owner of the user"
// @Param   name    formData string true "The name of the user"
// @Param   mfaType formData string true "The MFA auth type"
// @Param   stepUpMfaType      formData string false "The type of a factor the user has, to show it with the request (app/sms/email)"
// @Param   stepUpPasscode     formData string false "A passcode of that factor"
// @Param   stepUpRecoveryCode formData string false "A recovery code, instead of the passcode"
// @Success 200 {object} controllers.Response The Response object
// @router /mfa/setup/enable [post]
func (c *ApiController) MfaSetupEnable() {
	owner := c.Ctx.Request.Form.Get("owner")
	name := c.Ctx.Request.Form.Get("name")
	mfaType := c.Ctx.Request.Form.Get("mfaType")
	secret := c.Ctx.Request.Form.Get("secret")
	dest := c.Ctx.Request.Form.Get("dest")
	countryCode := c.Ctx.Request.Form.Get("countryCode")
	recoveryCodes := c.Ctx.Request.Form.Get("recoveryCodes")

	user, err := object.GetUser(util.GetId(owner, name))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if user == nil {
		c.ResponseError("User doesn't exist")
		return
	}

	// through the user's own session, the factor turned on is the one set up and verified in this session, with
	// its recovery code, and a user who has a factor already showed one for it
	var state *mfaSetupState
	if c.isMfaSelfService(user) {
		state = c.getMfaSetupState(user, mfaType)
		if state == nil {
			c.ResponseErrorWithCode(object.MfaOutcomeBadRequest, "the MFA setup has expired or was not started in this session, please start it again", object.MfaOutcomeBadRequest)
			return
		}
		if user.IsMfaEnabled() && !state.Fresh && !c.checkFreshMfa(user) {
			return
		}
		if mfaType == object.TotpType {
			secret = state.Secret
		}
		recoveryCodes = state.RecoveryCode
	}

	config := &object.MfaProps{
		MfaType: mfaType,
	}

	if mfaType == object.TotpType {
		if secret == "" {
			c.ResponseError("totp secret is missing")
			return
		}
		config.Secret = secret
	} else if mfaType == object.EmailType {
		if user.Email == "" {
			if dest == "" {
				c.ResponseError("destination is missing")
				return
			}
			user.Email = dest
		}
	} else if mfaType == object.SmsType {
		if user.Phone == "" {
			if dest == "" {
				c.ResponseError("destination is missing")
				return
			}
			user.Phone = dest
			if countryCode == "" {
				c.ResponseError("country code is missing")
				return
			}
			user.CountryCode = countryCode
		}
	} else if mfaType == object.RadiusType {
		if dest == "" {
			c.ResponseError("RADIUS username is missing")
			return
		}
		config.Secret = dest
		if secret == "" {
			c.ResponseError("RADIUS provider is missing")
			return
		}
		config.URL = secret
	} else if mfaType == object.PushType {
		if dest == "" {
			c.ResponseError("push notification receiver is missing")
			return
		}
		config.Secret = dest
		if secret == "" {
			c.ResponseError("push notification provider is missing")
			return
		}
		config.URL = secret
	}

	if recoveryCodes == "" {
		c.ResponseError("recovery codes is missing")
		return
	}
	config.RecoveryCodes = []string{recoveryCodes}

	mfaUtil := object.GetMfaUtil(mfaType, config)
	if mfaUtil == nil {
		c.ResponseError("Invalid multi-factor authentication type")
		return
	}

	organization, err := object.GetOrganizationByUser(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if !object.IsMfaTypeAllowed(organization, user, mfaType) {
		c.ResponseError(fmt.Sprintf("the MFA type: %s is not allowed by the MFA items", mfaType))
		return
	}

	if !c.checkMfaSetupDest(user, mfaType) {
		return
	}

	if state != nil && state.Verified != getMfaSetupEnabledFingerprint(user, mfaType, secret, dest) {
		c.ResponseErrorWithCode(object.MfaOutcomeBadRequest, "the MFA setup has not been verified", object.MfaOutcomeBadRequest)
		return
	}

	err = mfaUtil.Enable(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.DelSession(mfaSetupVerifiedDestSession)
	c.clearMfaSetupState()
	c.ResponseOk(http.StatusText(http.StatusOK))
}

// getMfaSetupEnabledFingerprint names what setup/enable turns on, as getMfaSetupFingerprint names what a code
// was verified for: an email or SMS factor is the user's own address or phone, see SmsMfa.Enable
func getMfaSetupEnabledFingerprint(user *object.User, mfaType string, secret string, dest string) string {
	switch mfaType {
	case object.EmailType:
		return getMfaSetupFingerprint(mfaType, "", user.Email, "")
	case object.SmsType:
		return getMfaSetupFingerprint(mfaType, "", user.Phone, user.CountryCode)
	default:
		return getMfaSetupFingerprint(mfaType, secret, dest, "")
	}
}

// DeleteMfa
// @Title DeleteMfa
// @Tag MFA API
// @Description Delete MFA. Through the user's own session or access token, a user who has a factor shows one first: within 5 minutes of passing /api/mfa/verify or the MFA step of the sign-in in the same session, or in the request with stepUpMfaType and stepUpPasscode, or stepUpRecoveryCode; else the answer is an error with the data mfa-step-up-required. An application with client credentials and an administrator of another user are not asked.
// @Param   owner formData string true "The owner of the user"
// @Param   name  formData string true "The name of the user"
// @Param   stepUpMfaType      formData string false "The type of a factor the user has, to show it with the request (app/sms/email)"
// @Param   stepUpPasscode     formData string false "A passcode of that factor"
// @Param   stepUpRecoveryCode formData string false "A recovery code, instead of the passcode"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-mfa/ [post]
func (c *ApiController) DeleteMfa() {
	owner := c.Ctx.Request.Form.Get("owner")
	name := c.Ctx.Request.Form.Get("name")
	userId := util.GetId(owner, name)

	user, err := object.GetUser(userId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError("User doesn't exist")
		return
	}

	// through the user's own session, the factors are removed only by someone who just showed one
	if c.isMfaSelfService(user) && !c.checkFreshMfa(user) {
		return
	}

	err = object.DisabledMultiFactorAuth(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(object.GetAllMfaProps(user, true))
}

// SetPreferredMfa
// @Title SetPreferredMfa
// @Tag MFA API
// @Description Set preferred MFA
// @Param   mfaType formData string true "The MFA type to set as preferred"
// @Param   owner   formData string true "The owner of the user"
// @Param   name    formData string true "The name of the user"
// @Success 200 {object} controllers.Response The Response object
// @router /set-preferred-mfa [post]
func (c *ApiController) SetPreferredMfa() {
	mfaType := c.Ctx.Request.Form.Get("mfaType")
	owner := c.Ctx.Request.Form.Get("owner")
	name := c.Ctx.Request.Form.Get("name")
	userId := util.GetId(owner, name)

	user, err := object.GetUser(userId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError("User doesn't exist")
		return
	}

	err = object.SetPreferredMultiFactorAuth(user, mfaType)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(object.GetAllMfaProps(user, true))
}
