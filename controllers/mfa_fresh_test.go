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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/beego/beego/v2/server/web/session"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestIsMfaFreshValue(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	value := util.StructToJson(&mfaFreshFactor{UserId: "org/alice", Time: now.Add(-time.Minute).Unix()})

	cases := []struct {
		name   string
		value  string
		userId string
		now    time.Time
		want   bool
	}{
		{"the user, a minute ago", value, "org/alice", now, true},
		{"another user", value, "org/bob", now, false},
		{"too long ago", value, "org/alice", now.Add(mfaFreshTimeout), false},
		{"in the future", value, "org/alice", now.Add(-2 * time.Minute), false},
		{"nothing", "", "org/alice", now, false},
		{"no user", value, "", now, false},
		{"not JSON", "org/alice", "org/alice", now, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isMfaFreshValue(tc.value, tc.userId, tc.now); got != tc.want {
				t.Fatalf("isMfaFreshValue() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseMfaSetupState(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	value := util.StructToJson(&mfaSetupState{UserId: "org/alice", MfaType: object.TotpType, Secret: "S", RecoveryCode: "R", CreatedTime: now.Unix()})

	if state := parseMfaSetupState(value, "org/alice", object.TotpType, now.Add(time.Minute)); state == nil || state.Secret != "S" || state.RecoveryCode != "R" {
		t.Fatalf("the setup of the session was not found: %+v", state)
	}
	for name, state := range map[string]*mfaSetupState{
		"another user":  parseMfaSetupState(value, "org/bob", object.TotpType, now),
		"another type":  parseMfaSetupState(value, "org/alice", object.EmailType, now),
		"too old":       parseMfaSetupState(value, "org/alice", object.TotpType, now.Add(mfaSetupTimeout+time.Second)),
		"no setup":      parseMfaSetupState("", "org/alice", object.TotpType, now),
		"not JSON":      parseMfaSetupState("{", "org/alice", object.TotpType, now),
		"in the future": parseMfaSetupState(value, "org/alice", object.TotpType, now.Add(-time.Minute)),
	} {
		if state != nil {
			t.Fatalf("%s: a setup was found: %+v", name, state)
		}
	}
}

func TestIsMfaSelfServiceCaller(t *testing.T) {
	cases := []struct {
		name             string
		callerId         string
		isAdminOfAnother bool
		want             bool
	}{
		{"the user", "org/alice", false, true},
		{"an application with client credentials", "app/app-1", false, false},
		{"an administrator of another user", "org/admin", true, false},
		{"anyone else", "org/mallory", false, true},
		{"a dynamically registered client", "app-dcr/dcr-1", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isMfaSelfServiceCaller(tc.callerId, "org/alice", tc.isAdminOfAnother); got != tc.want {
				t.Fatalf("isMfaSelfServiceCaller() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMfaSetupFingerprints(t *testing.T) {
	user := &object.User{Email: "alice@example.com", Phone: "2025550100", CountryCode: "US"}

	if getMfaSetupFingerprint(object.EmailType, "", "alice@example.com", "") != getMfaSetupEnabledFingerprint(user, object.EmailType, "", "attacker@example.com") {
		t.Fatal("the address verified is not the one turned on")
	}
	if getMfaSetupFingerprint(object.SmsType, "", "2025550100", "US") != getMfaSetupEnabledFingerprint(user, object.SmsType, "", "") {
		t.Fatal("the phone verified is not the one turned on")
	}
	if getMfaSetupFingerprint(object.TotpType, "SECRET", "", "") == getMfaSetupEnabledFingerprint(user, object.TotpType, "OTHER", "") {
		t.Fatal("another TOTP secret matches")
	}
	if getMfaSetupFingerprint(object.PushType, "admin/p1", "phone-1", "") == getMfaSetupEnabledFingerprint(user, object.PushType, "admin/p1", "phone-2") {
		t.Fatal("another push receiver matches")
	}
}

const (
	testMfaOrg    = "org-mfa"
	testMfaApp    = "app-mfa"
	testMfaClient = "client-mfa"
)

var (
	initMfaTestDbOnce sync.Once
	mfaTestDbDir      string
)

func TestMain(m *testing.M) {
	code := m.Run()
	if mfaTestDbDir != "" {
		_ = os.RemoveAll(mfaTestDbDir)
	}
	os.Exit(code)
}

// initMfaTestDb points Casdoor at a SQLite database of the test binary, with all its tables. The settings stay
// for the whole binary, the database outlives one test.
func initMfaTestDb(t *testing.T) {
	t.Helper()

	initMfaTestDbOnce.Do(func() {
		var err error
		mfaTestDbDir, err = os.MkdirTemp("", "casdoor-mfa-test-")
		if err != nil {
			t.Fatal(err)
		}
		for key, value := range map[string]string{
			"driverName":     "sqlite3",
			"dataSourceName": "file:" + filepath.Join(mfaTestDbDir, "mfa.db") + "?_pragma=busy_timeout(30000)",
			"dbName":         "",
		} {
			if err = os.Setenv(key, value); err != nil {
				t.Fatal(err)
			}
		}
		object.InitAdapter()
		object.CreateTables()
	})
}

func addMfaTestRows(t *testing.T, name string, totpSecret string) *object.User {
	t.Helper()

	if organization, err := object.GetOrganization(util.GetId("admin", testMfaOrg)); err != nil {
		t.Fatal(err)
	} else if organization == nil {
		if _, err = object.AddOrganization(&object.Organization{Owner: "admin", Name: testMfaOrg, PasswordType: "plain"}); err != nil {
			t.Fatal(err)
		}
		if _, err = object.AddApplication(&object.Application{Owner: "admin", Name: testMfaApp, Organization: testMfaOrg, ClientId: testMfaClient}, "en"); err != nil {
			t.Fatal(err)
		}
	}

	user := &object.User{
		Owner: testMfaOrg, Name: name, Id: util.GenerateUUID(), SignupApplication: testMfaApp, CreatedTime: util.GetCurrentTime(),
		TotpSecret: totpSecret, RecoveryCodes: []string{"recovery-" + name},
	}
	if totpSecret != "" {
		user.PreferredMfaType = object.TotpType
	}
	if _, err := object.AddUser(user, "en"); err != nil {
		t.Fatal(err)
	}
	return user
}

func newMfaTestSession(t *testing.T) session.Store {
	t.Helper()

	manager, err := session.NewManager("memory", &session.ManagerConfig{CookieName: "casdoor_session_id", Gclifetime: 3600})
	if err != nil {
		t.Fatal(err)
	}
	store, err := manager.SessionStart(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// callMfaApi runs an action of the controller for the caller, in the session of a browser
func callMfaApi(t *testing.T, store session.Store, callerId string, form url.Values, action func(c *ApiController)) *Response {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/api/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(rec, req)
	ctx.Input.CruSession = store
	ctx.Input.SetData("currentUserId", callerId)

	c := &ApiController{}
	c.Init(ctx, "ApiController", "MfaTest", c)
	action(c)

	resp := &Response{}
	if err := json.Unmarshal(rec.Body.Bytes(), resp); err != nil {
		t.Fatalf("the answer is not JSON: %q", rec.Body.String())
	}
	return resp
}

func requireMfaRefusal(t *testing.T, resp *Response, outcome string) {
	t.Helper()

	if resp.Status != "error" || resp.Data != outcome {
		t.Fatalf("the answer is %s %v (%s), want the refusal %s", resp.Status, resp.Data, resp.Msg, outcome)
	}
}

func requireMfaOk(t *testing.T, resp *Response) {
	t.Helper()

	if resp.Status != "ok" {
		t.Fatalf("the answer is an error: %s (%v)", resp.Msg, resp.Data)
	}
}

func totpTestCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()

	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: object.MfaTotpPeriodInSeconds, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func newTotpTestSecret(t *testing.T) string {
	t.Helper()

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test", AccountName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return key.Secret()
}

// Finding 2 of the review: a session or an access token of the user replaced or removed the factor without one
func TestSelfServiceMfaChangesNeedAFreshFactor(t *testing.T) {
	initMfaTestDb(t)
	secret := newTotpTestSecret(t)
	user := addMfaTestRows(t, "alice", secret)
	userForm := url.Values{"owner": {user.Owner}, "name": {user.Name}}
	withForm := func(extra url.Values) url.Values {
		form := url.Values{}
		for key, values := range userForm {
			form[key] = values
		}
		for key, values := range extra {
			form[key] = values
		}
		return form
	}

	browser := newMfaTestSession(t)
	// a user with a factor sets up another one only after showing one
	requireMfaRefusal(t, callMfaApi(t, browser, user.GetId(), withForm(url.Values{"mfaType": {object.TotpType}}), (*ApiController).MfaSetupInitiate), object.MfaOutcomeStepUpRequired)
	requireMfaRefusal(t, callMfaApi(t, browser, user.GetId(), userForm, (*ApiController).DeleteMfa), object.MfaOutcomeStepUpRequired)

	now := time.Now()
	requireMfaOk(t, callMfaApi(t, browser, user.GetId(), url.Values{"mfaType": {object.TotpType}, "passcode": {totpTestCode(t, secret, now)}}, (*ApiController).MfaVerify))

	resp := callMfaApi(t, browser, user.GetId(), withForm(url.Values{"mfaType": {object.TotpType}}), (*ApiController).MfaSetupInitiate)
	requireMfaOk(t, resp)
	props := resp.Data.(map[string]interface{})
	newSecret := props["secret"].(string)
	recoveryCode := props["recoveryCodes"].([]interface{})[0].(string)

	attacker := newTotpTestSecret(t)
	enable := withForm(url.Values{"mfaType": {object.TotpType}, "secret": {attacker}, "recoveryCodes": {"attacker-code"}})
	// not before setup/verify passed a code of the secret of the setup
	requireMfaRefusal(t, callMfaApi(t, browser, user.GetId(), enable, (*ApiController).MfaSetupEnable), object.MfaOutcomeBadRequest)
	// nor with a code of another secret
	requireMfaRefusal(t, callMfaApi(t, browser, user.GetId(), withForm(url.Values{"mfaType": {object.TotpType}, "secret": {attacker}, "passcode": {totpTestCode(t, attacker, now)}}), (*ApiController).MfaSetupVerify), object.MfaOutcomeBadRequest)

	requireMfaOk(t, callMfaApi(t, browser, user.GetId(), withForm(url.Values{"mfaType": {object.TotpType}, "passcode": {totpTestCode(t, newSecret, now)}}), (*ApiController).MfaSetupVerify))
	// the secret and the recovery code turned on are the ones of the setup, not the ones the request names
	requireMfaOk(t, callMfaApi(t, browser, user.GetId(), enable, (*ApiController).MfaSetupEnable))
	stored, err := object.GetUser(user.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if stored.TotpSecret != newSecret || !util.InSlice(stored.RecoveryCodes, recoveryCode) || util.InSlice(stored.RecoveryCodes, "attacker-code") {
		t.Fatalf("turned on the secret %q with the recovery codes %v", stored.TotpSecret, stored.RecoveryCodes)
	}

	// another browser, or the same one later, has to show a factor to remove them
	other := newMfaTestSession(t)
	requireMfaRefusal(t, callMfaApi(t, other, user.GetId(), userForm, (*ApiController).DeleteMfa), object.MfaOutcomeStepUpRequired)
	requireMfaRefusal(t, callMfaApi(t, other, user.GetId(), withForm(url.Values{"stepUpMfaType": {object.TotpType}, "stepUpPasscode": {"000000"}}), (*ApiController).DeleteMfa), object.MfaOutcomeWrongCode)
	requireMfaOk(t, callMfaApi(t, other, user.GetId(), withForm(url.Values{"stepUpMfaType": {object.TotpType}, "stepUpPasscode": {totpTestCode(t, newSecret, now.Add(30*time.Second))}}), (*ApiController).DeleteMfa))
	if stored, err = object.GetUser(user.GetId()); err != nil || stored.IsMfaEnabled() {
		t.Fatalf("the factors were not removed: %v", err)
	}
}

// an application with its client credentials checks the user itself, as iam and cloud-be do
func TestApplicationMfaChangesKeepTheirContract(t *testing.T) {
	initMfaTestDb(t)
	user := addMfaTestRows(t, "bob", newTotpTestSecret(t))
	app := "app/" + testMfaApp
	browser := newMfaTestSession(t)

	resp := callMfaApi(t, browser, app, url.Values{"owner": {user.Owner}, "name": {user.Name}, "mfaType": {object.TotpType}}, (*ApiController).MfaSetupInitiate)
	requireMfaOk(t, resp)
	secret := resp.Data.(map[string]interface{})["secret"].(string)
	now := time.Now()
	requireMfaOk(t, callMfaApi(t, browser, app, url.Values{"owner": {user.Owner}, "name": {user.Name}, "mfaType": {object.TotpType}, "secret": {secret}, "passcode": {totpTestCode(t, secret, now)}}, (*ApiController).MfaSetupVerify))
	requireMfaOk(t, callMfaApi(t, browser, app, url.Values{"owner": {user.Owner}, "name": {user.Name}, "mfaType": {object.TotpType}, "secret": {secret}, "recoveryCodes": {"app-code"}}, (*ApiController).MfaSetupEnable))
	requireMfaOk(t, callMfaApi(t, browser, app, url.Values{"owner": {user.Owner}, "name": {user.Name}}, (*ApiController).DeleteMfa))
}

func TestMfaVerifyOutcomesSurviveTheErrorMask(t *testing.T) {
	initMfaTestDb(t)
	user := addMfaTestRows(t, "carol", newTotpTestSecret(t))
	app := "app/" + testMfaApp
	browser := newMfaTestSession(t)
	t.Setenv("enableErrorMask2", "true")

	form := url.Values{"owner": {user.Owner}, "name": {user.Name}, "mfaType": {object.TotpType}, "passcode": {"000000"}}
	resp := callMfaApi(t, browser, app, form, (*ApiController).MfaVerify)
	requireMfaRefusal(t, resp, object.MfaOutcomeWrongCode)
	if strings.Contains(resp.Msg, "remaining") {
		t.Fatalf("the message was not masked: %s", resp.Msg)
	}

	form.Set("mfaType", object.EmailType)
	requireMfaRefusal(t, callMfaApi(t, browser, app, form, (*ApiController).MfaVerify), object.MfaOutcomeNotEnrolled)
	form.Set("mfaType", object.PushType)
	requireMfaRefusal(t, callMfaApi(t, browser, app, form, (*ApiController).MfaVerify), object.MfaOutcomeBadRequest)
	requireMfaRefusal(t, callMfaApi(t, browser, app, url.Values{"owner": {user.Owner}, "name": {user.Name}, "mfaType": {object.PushType}}, (*ApiController).MfaSend), object.MfaOutcomeBadRequest)
	requireMfaRefusal(t, callMfaApi(t, browser, app, url.Values{"owner": {"another-org"}, "name": {user.Name}, "mfaType": {object.TotpType}, "passcode": {"000000"}}, (*ApiController).MfaVerify), object.MfaOutcomeUnauthorized)
	requireMfaRefusal(t, callMfaApi(t, browser, "", form, (*ApiController).MfaVerify), object.MfaOutcomeUnauthorized)

	// a proof is made only for an application, never for a plain session of the user
	requireMfaRefusal(t, callMfaApi(t, browser, user.GetId(), url.Values{"mfaType": {object.TotpType}, "passcode": {"000000"}, "proof": {"true"}}, (*ApiController).MfaVerify), object.MfaOutcomeBadRequest)
}
