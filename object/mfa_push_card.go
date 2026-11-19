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
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/casdoor/casdoor/action"
	"github.com/casdoor/casdoor/edition"
	"github.com/casdoor/casdoor/notification"
	"github.com/casdoor/casdoor/util"
)

const (
	PushChallengePending  = "Pending"
	PushChallengeApproved = "Approved"
	PushChallengeDenied   = "Denied"
	PushChallengeExpired  = "Expired"

	pushChallengeLifetime = 5 * time.Minute
)

// A push is asked for a sign-in waiting for its second factor, or for a push factor being set up
const (
	PushPurposeSignin = "signin"
	PushPurposeSetup  = "setup"
)

// PushChallenge is a sign-in, or a setup, waiting for the user to confirm it on the phone. Its id is what the page
// that asked for it polls and then sends as the passcode; the approval takes another value, the approval token,
// which is only in the link sent to the phone: whoever asked for a push can't approve it.
type PushChallenge struct {
	Id            string    `json:"id"`
	UserId        string    `json:"userId"`
	Purpose       string    `json:"purpose"`
	Provider      string    `json:"-"`
	Receiver      string    `json:"-"`
	Application   string    `json:"application"`
	Ip            string    `json:"ip"`
	Location      string    `json:"location"`
	UserAgent     string    `json:"userAgent"`
	Status        string    `json:"status"`
	CreatedTime   time.Time `json:"createdTime"`
	approvalToken string
}

var (
	// id -> *PushChallenge
	pushChallenges sync.Map
	// approval token -> id
	pushApprovals sync.Map
	// guards the status of the challenges, which the page polling, the phone and the check change
	pushChallengeLock sync.Mutex
)

// loadPushChallenge returns the stored challenge, expired as time goes, under pushChallengeLock
func loadPushChallenge(id string) *PushChallenge {
	if id == "" {
		return nil
	}
	value, ok := pushChallenges.Load(id)
	if !ok {
		return nil
	}
	challenge := value.(*PushChallenge)
	if challenge.Status == PushChallengePending && time.Since(challenge.CreatedTime) > pushChallengeLifetime {
		challenge.Status = PushChallengeExpired
	}
	if time.Since(challenge.CreatedTime) > 2*pushChallengeLifetime {
		deletePushChallenge(challenge)
		return nil
	}
	return challenge
}

func deletePushChallenge(challenge *PushChallenge) {
	pushChallenges.Delete(challenge.Id)
	pushApprovals.Delete(challenge.approvalToken)
}

func getPushChallengeIdByToken(token string) string {
	if token == "" {
		return ""
	}
	value, ok := pushApprovals.Load(token)
	if !ok {
		return ""
	}
	return value.(string)
}

// GetPushChallenge returns a copy of the challenge, by its id (the page waiting for it) or by its approval token
// (the confirmation page opened from the phone), never with the approval token in it
func GetPushChallenge(idOrToken string) *PushChallenge {
	pushChallengeLock.Lock()
	defer pushChallengeLock.Unlock()

	challenge := loadPushChallenge(idOrToken)
	if challenge == nil {
		challenge = loadPushChallenge(getPushChallengeIdByToken(idOrToken))
	}
	if challenge == nil {
		return nil
	}
	snapshot := *challenge
	snapshot.approvalToken = ""
	return &snapshot
}

// AnswerPushChallenge records the user's answer on the confirmation page, which only the approval token of the
// link sent to the phone opens: the id that the page asking for the push holds approves nothing
func AnswerPushChallenge(token string, approve bool) (*PushChallenge, error) {
	pushChallengeLock.Lock()
	defer pushChallengeLock.Unlock()

	challenge := loadPushChallenge(getPushChallengeIdByToken(token))
	if challenge == nil {
		return nil, errors.New("the sign-in request doesn't exist or has expired")
	}
	if challenge.Status != PushChallengePending {
		return nil, fmt.Errorf("the sign-in request has been %s", challenge.Status)
	}
	if approve {
		challenge.Status = PushChallengeApproved
	} else {
		challenge.Status = PushChallengeDenied
	}

	snapshot := *challenge
	snapshot.approvalToken = ""
	return &snapshot, nil
}

// consumePushChallenge is the passcode check of the push MFA: the passcode is the id of a challenge that the
// user approved for the same provider, receiver and purpose, and for the user when it is given. It works once.
func consumePushChallenge(id string, provider string, receiver string, userId string, purpose string) error {
	pushChallengeLock.Lock()
	defer pushChallengeLock.Unlock()

	challenge := loadPushChallenge(id)
	if challenge == nil || challenge.Provider != provider || challenge.Receiver != receiver || challenge.Purpose != purpose || (userId != "" && challenge.UserId != userId) {
		return NewMfaError(MfaOutcomeWrongCode, "the sign-in request doesn't exist or has expired, please send it again")
	}
	switch challenge.Status {
	case PushChallengeApproved:
		if _, loaded := pushChallenges.LoadAndDelete(id); !loaded {
			return NewMfaError(MfaOutcomeWrongCode, "the sign-in request doesn't exist or has expired, please send it again")
		}
		pushApprovals.Delete(challenge.approvalToken)
		return nil
	case PushChallengeDenied:
		deletePushChallenge(challenge)
		return NewMfaError(MfaOutcomeWrongCode, "the sign-in request was denied on the phone")
	case PushChallengeExpired:
		return NewMfaError(MfaOutcomeWrongCode, "the sign-in request has expired, please send it again")
	default:
		return NewMfaError(MfaOutcomeWrongCode, "the sign-in request hasn't been confirmed on the phone yet")
	}
}

// SendPushChallenge sends a card with a confirmation link to the receiver through the provider: the enterprise
// app of a WeCom, DingTalk or Lark login provider, or a notification provider. The link carries the approval
// token, so it is built only on an origin that the configuration names: a Host header of the request asking for
// the push must not send the token somewhere else.
func SendPushChallenge(userId string, providerId string, receiver string, application string, purpose string, clientIp string, userAgent string, host string) (*PushChallenge, error) {
	if err := edition.Require(edition.Commercial, edition.FeaturePushMfa); err != nil {
		return nil, err
	}
	if providerId == "" || receiver == "" {
		return nil, errors.New("push notification provider and receiver are required")
	}
	if purpose != PushPurposeSignin && purpose != PushPurposeSetup {
		return nil, errors.New("the purpose of the push notification is not known")
	}

	origin, ok := getTrustedOriginFrontend(host)
	if !ok {
		return nil, errors.New("please set \"origin\" in conf/app.conf to send push notifications")
	}

	provider, err := GetProvider(providerId)
	if err != nil {
		return nil, err
	}
	if provider == nil {
		return nil, fmt.Errorf("the provider: %s does not exist", providerId)
	}

	challenge := &PushChallenge{
		Id:            util.GenerateId() + util.GenerateId(),
		UserId:        userId,
		Purpose:       purpose,
		Provider:      providerId,
		Receiver:      receiver,
		Application:   application,
		Ip:            clientIp,
		Location:      getIpLocation(clientIp),
		UserAgent:     userAgent,
		Status:        PushChallengePending,
		CreatedTime:   time.Now(),
		approvalToken: util.GenerateId() + util.GenerateId(),
	}

	confirmUrl := fmt.Sprintf("%s/mfa/push-confirm/%s", origin, challenge.approvalToken)
	title := "Confirm your sign-in"
	if purpose == PushPurposeSetup {
		title = "Confirm the push notification setup"
	}
	description := fmt.Sprintf("Account: %s\nApplication: %s\nIP address: %s %s\nTime: %s\nOpen the link and approve it if it is you. It expires in 5 minutes.",
		userId, application, clientIp, challenge.Location, challenge.CreatedTime.Format("2006-01-02 15:04:05"))

	switch {
	case provider.Category == "Notification" && provider.Type == ProviderTypePlugin:
		// an action from the Marketplace, such as an app message of WeCom, DingTalk or Lark
		var m *action.Module
		m, _, err = getInstalledAction(provider.Owner, provider.SubType, "push")
		if err == nil {
			err = action.SendPush(m, getPushActionConfig(provider), receiver, title, description, confirmUrl)
		}
	case provider.Category == "Notification":
		err = sendNotificationCard(provider, receiver, title, description+"\n"+confirmUrl)
	default:
		err = fmt.Errorf("the provider: %s can't send push notifications, use a notification provider", providerId)
	}
	if err != nil {
		return nil, err
	}

	pushChallenges.Store(challenge.Id, challenge)
	pushApprovals.Store(challenge.approvalToken, challenge.Id)

	snapshot := *challenge
	snapshot.approvalToken = ""
	return &snapshot, nil
}

func getPushActionConfig(provider *Provider) *action.Config {
	return &action.Config{
		ClientId:      provider.ClientId,
		ClientSecret:  provider.ClientSecret,
		ClientId2:     provider.AppId,
		ClientSecret2: provider.ClientSecret2,
		Host:          provider.Host,
		Metadata:      provider.Metadata,
	}
}

// GetPushReceiverField returns the user field that holds the receiver of a push provider of type Plugin, so that
// the receiver is filled in when the user has linked that account, e.g. "wecom"
func GetPushReceiverField(provider *Provider) string {
	if provider == nil || provider.Type != ProviderTypePlugin {
		return ""
	}
	_, file, err := getInstalledAction(provider.Owner, provider.SubType, "push")
	if err != nil {
		return ""
	}
	return file.ReceiverField
}

// GetUserFieldValue returns the value of one of the account fields that a push receiver may be taken from
func GetUserFieldValue(user *User, field string) string {
	switch field {
	case "wecom":
		return user.Wecom
	case "dingtalk":
		return user.DingTalk
	case "lark":
		return user.Lark
	case "email":
		return user.Email
	case "phone":
		return user.Phone
	}
	return ""
}

func sendNotificationCard(provider *Provider, receiver string, title string, content string) error {
	notifier, err := notification.GetNotificationProvider(provider.Type, provider.ClientId, provider.ClientSecret, provider.ClientId2, provider.ClientSecret2,
		provider.AppId, receiver, provider.Method, title, provider.Metadata, provider.RegionId)
	if err != nil {
		return err
	}
	if notifier == nil {
		return errors.New("notification provider is not supported")
	}
	restrictNotificationClient(notifier, util.NewInternetOnlyHttpClient(30*time.Second))
	return notifier.Send(context.Background(), title, content)
}
