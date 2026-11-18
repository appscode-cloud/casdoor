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
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

var errMfaPushTooFast = errors.New("please wait for 20 seconds before sending again")

type mfaStepUpParams struct {
	Owner        string `json:"owner"`
	Name         string `json:"name"`
	MfaType      string `json:"mfaType"`
	Passcode     string `json:"passcode"`
	RecoveryCode string `json:"recoveryCode"`
	Action       string `json:"action"`
	Nonce        string `json:"nonce"`
	Proof        bool   `json:"proof"`
}

type mfaStepUpSubject struct {
	user        *object.User
	application *object.Application
	// the user, or the application when it acts for the user with its client credentials
	caller string
}

// MfaVerifyResult is the response of a passed check: it never carries the factor itself
type MfaVerifyResult struct {
	Verified   bool   `json:"verified"`
	ProofToken string `json:"proofToken,omitempty"`
	ExpiresIn  int    `json:"expiresIn,omitempty"`
}

func (c *ApiController) getMfaStepUpParams() *mfaStepUpParams {
	form := c.Ctx.Request.Form
	params := &mfaStepUpParams{
		Owner:        form.Get("owner"),
		Name:         form.Get("name"),
		MfaType:      form.Get("mfaType"),
		Passcode:     form.Get("passcode"),
		RecoveryCode: form.Get("recoveryCode"),
		Action:       form.Get("action"),
		Nonce:        form.Get("nonce"),
		Proof:        form.Get("proof") == "true",
	}

	if strings.HasPrefix(c.Ctx.Input.Header("Content-Type"), "application/json") && len(c.Ctx.Input.RequestBody) > 0 {
		err := json.Unmarshal(c.Ctx.Input.RequestBody, params)
		if err != nil {
			c.ResponseError(err.Error())
			return nil
		}
	}
	return params
}

// getMfaStepUpSubject resolves who is checked: the signed-in user, or for an application that signed in
// with its client credentials the user it names, only one of its own organization
func (c *ApiController) getMfaStepUpSubject(params *mfaStepUpParams) *mfaStepUpSubject {
	callerId := c.GetSessionUsername()
	if callerId == "" {
		c.ResponseError(c.T("general:Please sign in first"))
		return nil
	}

	subject := &mfaStepUpSubject{caller: callerId}
	var err error
	if object.IsAppUser(callerId) {
		return c.getMfaStepUpSubjectOfApplication(subject, params)
	}

	// the user is the one signed in, never one that the request names
	if (params.Owner != "" || params.Name != "") && util.GetId(params.Owner, params.Name) != callerId {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return nil
	}

	subject.user, err = object.GetUser(callerId)
	if err != nil {
		c.ResponseError(err.Error())
		return nil
	}
	if !c.checkMfaStepUpUser(subject.user) {
		return nil
	}

	_, clientId := c.GetSessionOidc()
	if clientId != "" {
		subject.application, err = object.GetApplicationByClientId(clientId)
	} else {
		subject.application, err = object.GetApplicationByUser(subject.user)
	}
	if err != nil {
		c.ResponseError(err.Error())
		return nil
	}
	return subject
}

func (c *ApiController) getMfaStepUpSubjectOfApplication(subject *mfaStepUpSubject, params *mfaStepUpParams) *mfaStepUpSubject {
	// a dynamically registered client is created by anyone, it never acts for a user
	if !strings.HasPrefix(subject.caller, "app/") {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return nil
	}

	application, err := object.GetApplicationByUserId(subject.caller)
	if err != nil {
		c.ResponseError(err.Error())
		return nil
	}
	if application == nil || params.Owner != application.Organization || params.Name == "" {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return nil
	}

	user, err := object.GetUser(util.GetId(params.Owner, params.Name))
	if err != nil {
		c.ResponseError(err.Error())
		return nil
	}
	if user != nil && !canApplicationCheckMfaOf(application, user) {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return nil
	}
	if !c.checkMfaStepUpUser(user) {
		return nil
	}

	subject.user, subject.application = user, application
	return subject
}

// canApplicationCheckMfaOf tells that the user belongs to the organization of the application, an
// application of the built-in organization is no exception
func canApplicationCheckMfaOf(application *object.Application, user *object.User) bool {
	return application != nil && user != nil && application.Organization != "" && application.Organization == user.Owner
}

func (c *ApiController) checkMfaStepUpUser(user *object.User) bool {
	if user == nil || user.IsDeleted {
		c.ResponseError(c.T("general:The user doesn't exist"))
		return false
	}
	if user.IsForbidden {
		c.ResponseError(object.GetUserForbiddenMessage(user, c.GetAcceptLanguage()))
		return false
	}
	return true
}

func (c *ApiController) addMfaStepUpRecord(action string, subject *mfaStepUpSubject, mfaType string, err error) {
	clientIp := util.GetClientIpFromRequest(c.Ctx.Request)
	lang := c.GetAcceptLanguage()
	util.SafeGoroutine(func() {
		object.AddMfaStepUpRecord(action, subject.user, subject.application, mfaType, subject.caller, clientIp, lang, err)
	})
}

// MfaVerify
// @Title MfaVerify
// @Tag MFA API
// @Description verify a factor that the signed-in user enrolled, e.g. before a sensitive action. The factor is always the stored one, the master verification code of the organization is not accepted, and a passcode works once. An application with client credentials may name the user (owner and name) of its own organization.
// @Param   mfaType      formData string true  "The enrolled MFA type (app/sms/email/push/radius)"
// @Param   passcode     formData string false "The passcode, or the id of the approved push request"
// @Param   recoveryCode formData string false "A recovery code, used instead of the passcode, it works once"
// @Param   owner        formData string false "The owner of the user, for an application with client credentials"
// @Param   name         formData string false "The name of the user, for an application with client credentials"
// @Param   proof        formData string false "true to get a signed, short-lived proof of the check"
// @Param   action       formData string false "The action that the proof approves, kept in the proof"
// @Param   nonce        formData string false "A value of the caller, kept in the proof"
// @Success 200 {object} controllers.Response The Response object
// @router /mfa/verify [post]
func (c *ApiController) MfaVerify() {
	params := c.getMfaStepUpParams()
	if params == nil {
		return
	}

	subject := c.getMfaStepUpSubject(params)
	if subject == nil {
		return
	}

	mfaType := params.MfaType
	if params.RecoveryCode != "" {
		mfaType = object.MfaRecoveryType
	}

	if params.Proof && subject.application == nil {
		c.ResponseError("the application of the check is not known")
		return
	}

	err := object.VerifyEnrolledMfa(subject.user, &object.MfaStepUpCheck{
		MfaType:      params.MfaType,
		Passcode:     params.Passcode,
		RecoveryCode: params.RecoveryCode,
		ClientIp:     util.GetClientIpFromRequest(c.Ctx.Request),
		Lang:         c.GetAcceptLanguage(),
	})
	c.addMfaStepUpRecord("mfa-verify", subject, mfaType, err)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	result := &MfaVerifyResult{Verified: true}
	if params.Proof {
		result.ProofToken, err = object.GenerateMfaProofToken(subject.application, subject.user, mfaType, params.Action, params.Nonce, time.Now(), c.Ctx.Request.Host)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		result.ExpiresIn = object.MfaProofLifetimeInSeconds
	}
	c.ResponseOk(result)
}

// MfaSend
// @Title MfaSend
// @Tag MFA API
// @Description send a code of the enrolled email, SMS or push factor of the signed-in user, to the destination stored in the user only
// @Param   mfaType formData string true  "The enrolled MFA type (email/sms/push)"
// @Param   owner   formData string false "The owner of the user, for an application with client credentials"
// @Param   name    formData string false "The name of the user, for an application with client credentials"
// @Success 200 {object} controllers.Response The Response object
// @router /mfa/send [post]
func (c *ApiController) MfaSend() {
	params := c.getMfaStepUpParams()
	if params == nil {
		return
	}

	subject := c.getMfaStepUpSubject(params)
	if subject == nil {
		return
	}

	if subject.application == nil {
		c.ResponseError("the application of the check is not known")
		return
	}

	var err error
	var challengeId string
	switch params.MfaType {
	case object.EmailType, object.SmsType:
		err = object.SendMfaStepUpCode(subject.application, subject.user, params.MfaType, util.GetClientIpFromRequest(c.Ctx.Request), c.Ctx.Request.Host, c.GetAcceptLanguage())
	case object.PushType:
		challengeId, err = c.sendMfaStepUpPush(subject)
	default:
		c.ResponseError("Invalid multi-factor authentication type")
		return
	}
	c.addMfaStepUpRecord("mfa-send", subject, params.MfaType, err)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if challengeId != "" {
		c.ResponseOk(challengeId)
		return
	}
	c.ResponseOk()
}

func (c *ApiController) sendMfaStepUpPush(subject *mfaStepUpSubject) (string, error) {
	mfaProps, err := object.GetEnrolledMfaProps(subject.user, object.PushType)
	if err != nil {
		return "", err
	}

	userId := subject.user.GetId()
	if value, ok := lastPushTimes.Load(userId); ok && time.Since(value.(time.Time)) < 20*time.Second {
		return "", errMfaPushTooFast
	}
	lastPushTimes.Store(userId, time.Now())

	origin := object.GetFrontendOrigin(c.Ctx.Request.Host)
	challenge, err := object.SendPushChallenge(userId, mfaProps.URL, mfaProps.Secret, subject.application.Name, util.GetClientIpFromRequest(c.Ctx.Request), c.Ctx.Request.UserAgent(), origin)
	if err != nil {
		return "", err
	}
	return challenge.Id, nil
}
