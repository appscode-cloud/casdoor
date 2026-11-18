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
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casdoor/casdoor/util"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	testStepUpOrg    = "org-stepup"
	testStepUpApp    = "app-stepup"
	testStepUpClient = "client-stepup"
	testMasterCode   = "246810"
)

// newStepUpTestDb gives the test its own SQLite database, so that it needs no server
func newStepUpTestDb(t *testing.T) {
	t.Helper()

	previous := ormer
	adapter, err := NewAdapter("sqlite3", filepath.Join(t.TempDir(), "stepup.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	ormer = adapter
	t.Cleanup(func() {
		ormer = previous
		adapter.close()
	})

	for _, table := range []interface{}{new(User), new(Organization), new(Application), new(Provider), new(Cert), new(VerificationRecord), new(Record), new(Webhook), new(Syncer)} {
		if err = ormer.Engine.Sync2(table); err != nil {
			t.Fatal(err)
		}
	}

	certPem, keyPem, err := generateRsaKeys(2048, 256, 1, "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	insertStepUpRows(t, &Cert{Owner: "admin", Name: "cert-built-in", KeyId: "kid-1", Certificate: certPem, PrivateKey: keyPem},
		&Organization{Owner: "admin", Name: testStepUpOrg, MasterVerificationCode: testMasterCode},
		&Application{Owner: "admin", Name: testStepUpApp, Organization: testStepUpOrg, ClientId: testStepUpClient, ExpireInHours: 1})
}

func insertStepUpRows(t *testing.T, rows ...interface{}) {
	t.Helper()
	for _, row := range rows {
		if _, err := ormer.Engine.Insert(row); err != nil {
			t.Fatal(err)
		}
	}
}

func newStepUpTestUser(t *testing.T, name string, totpSecret string) *User {
	t.Helper()

	user := &User{
		Owner: testStepUpOrg, Name: name, Id: util.GenerateUUID(), SignupApplication: testStepUpApp,
		TotpSecret: totpSecret, PreferredMfaType: TotpType, RecoveryCodes: []string{"recovery-1", "recovery-2"},
	}
	insertStepUpRows(t, user)
	return user
}

func newTestTotpSecret(t *testing.T) string {
	t.Helper()

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test", AccountName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return key.Secret()
}

func totpCodeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()

	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: MfaTotpPeriodInSeconds, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// pinStepUpClock keeps a test from straddling a time step
func pinStepUpClock(t *testing.T) time.Time {
	t.Helper()

	now := time.Now()
	mfaStepUpNow = func() time.Time { return now }
	t.Cleanup(func() { mfaStepUpNow = time.Now })
	return now
}

func stepUpCheck(mfaType string, passcode string) *MfaStepUpCheck {
	return &MfaStepUpCheck{MfaType: mfaType, Passcode: passcode, ClientIp: "203.0.113.7", Lang: "en"}
}

func TestMatchTotpStep(t *testing.T) {
	secret := newTestTotpSecret(t)
	now := time.Unix(1_800_000_000, 0)
	currentStep := now.Unix() / MfaTotpPeriodInSeconds

	cases := []struct {
		name     string
		at       time.Time
		wantStep int64
		wantOk   bool
	}{
		{"current step", now, currentStep, true},
		{"previous step", now.Add(-30 * time.Second), currentStep - 1, true},
		{"next step", now.Add(30 * time.Second), currentStep + 1, true},
		{"two steps back", now.Add(-60 * time.Second), 0, false},
		{"two steps ahead", now.Add(60 * time.Second), 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			step, ok := matchTotpStep(secret, totpCodeAt(t, secret, tc.at), now)
			if ok != tc.wantOk || step != tc.wantStep {
				t.Fatalf("matchTotpStep() = (%d, %v), want (%d, %v)", step, ok, tc.wantStep, tc.wantOk)
			}
		})
	}

	if _, ok := matchTotpStep(secret, "12345", now); ok {
		t.Fatal("a passcode of the wrong length was accepted")
	}
	if _, ok := matchTotpStep(secret, "", now); ok {
		t.Fatal("an empty passcode was accepted")
	}
}

func TestVerifyEnrolledMfaTotpIsNotAcceptedTwice(t *testing.T) {
	newStepUpTestDb(t)
	secret := newTestTotpSecret(t)
	user := newStepUpTestUser(t, "replay", secret)

	now := pinStepUpClock(t)
	current := totpCodeAt(t, secret, now)
	previous := totpCodeAt(t, secret, now.Add(-30*time.Second))
	next := totpCodeAt(t, secret, now.Add(30*time.Second))

	if err := VerifyEnrolledMfa(user, stepUpCheck(TotpType, current)); err != nil {
		t.Fatalf("a fresh code was rejected: %v", err)
	}
	if err := VerifyEnrolledMfa(user, stepUpCheck(TotpType, current)); err == nil {
		t.Fatal("the same code was accepted twice")
	}
	if err := VerifyEnrolledMfa(user, stepUpCheck(TotpType, previous)); err == nil {
		t.Fatal("a code of an earlier step was accepted after a later one")
	}
	if err := VerifyEnrolledMfa(user, stepUpCheck(TotpType, next)); err != nil {
		t.Fatalf("a code of a later step was rejected: %v", err)
	}
	if err := VerifyEnrolledMfa(user, stepUpCheck(TotpType, next)); err == nil {
		t.Fatal("the code of the later step was accepted twice")
	}

	stored, err := getUser(user.Owner, user.Name)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(30*time.Second).Unix() / MfaTotpPeriodInSeconds; stored.MfaTotpLastStep != want {
		t.Fatalf("the stored step is %d, want %d", stored.MfaTotpLastStep, want)
	}
}

func TestVerifyEnrolledMfaChecksOnlyTheEnrolledFactor(t *testing.T) {
	newStepUpTestDb(t)
	secret := newTestTotpSecret(t)
	user := newStepUpTestUser(t, "enrolled", secret)
	code := totpCodeAt(t, secret, pinStepUpClock(t))

	for _, mfaType := range []string{EmailType, SmsType, PushType, RadiusType, "", "unknown"} {
		if err := VerifyEnrolledMfa(user, stepUpCheck(mfaType, code)); err == nil {
			t.Fatalf("a valid TOTP code passed as the type %q that the user has not enrolled", mfaType)
		}
	}

	// a failed check of another type must not have used the code
	if err := VerifyEnrolledMfa(user, stepUpCheck(TotpType, code)); err != nil {
		t.Fatalf("the enrolled factor was rejected: %v", err)
	}
}

func TestVerifyEnrolledMfaRejectsTheMasterVerificationCode(t *testing.T) {
	newStepUpTestDb(t)
	secret := newTestTotpSecret(t)
	user := newStepUpTestUser(t, "master", secret)

	if _, ok := matchTotpStep(secret, testMasterCode, pinStepUpClock(t)); ok {
		t.Skip("the master code is the real code right now")
	}
	if err := VerifyEnrolledMfa(user, stepUpCheck(TotpType, testMasterCode)); err == nil {
		t.Fatal("the master verification code of the organization was accepted")
	}
}

func TestVerifyEnrolledMfaRecoveryCodeWorksOnce(t *testing.T) {
	newStepUpTestDb(t)
	user := newStepUpTestUser(t, "recovery", newTestTotpSecret(t))

	check := &MfaStepUpCheck{RecoveryCode: "recovery-1", ClientIp: "203.0.113.7", Lang: "en"}
	if err := VerifyEnrolledMfa(user, check); err != nil {
		t.Fatalf("a recovery code was rejected: %v", err)
	}
	if err := VerifyEnrolledMfa(user, check); err == nil {
		t.Fatal("a recovery code was accepted twice")
	}

	stored, err := getUser(user.Owner, user.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.RecoveryCodes) != 1 || stored.RecoveryCodes[0] != "recovery-2" {
		t.Fatalf("the other recovery codes were changed: %v", stored.RecoveryCodes)
	}

	both := &MfaStepUpCheck{RecoveryCode: "recovery-2", Passcode: "123456", ClientIp: "203.0.113.7", Lang: "en"}
	if err = VerifyEnrolledMfa(user, both); err == nil {
		t.Fatal("a passcode and a recovery code together were accepted")
	}
}

func TestVerifyEnrolledMfaEmailCodeWorksOnce(t *testing.T) {
	newStepUpTestDb(t)
	user := newStepUpTestUser(t, "mailer", "")
	user.MfaEmailEnabled, user.Email = true, "user@example.com"
	if _, err := ormer.Engine.ID([]interface{}{user.Owner, user.Name}).Cols("mfa_email_enabled", "email").Update(user); err != nil {
		t.Fatal(err)
	}

	organization := &Organization{Name: testStepUpOrg}
	provider := &Provider{Name: "mailer"}
	if err := AddToVerificationRecord(user, provider, organization, "203.0.113.7", "Email", user.Email, "135790"); err != nil {
		t.Fatal(err)
	}

	if err := VerifyEnrolledMfa(user, stepUpCheck(EmailType, "000000")); err == nil {
		t.Fatal("a wrong email code was accepted")
	}
	if err := VerifyEnrolledMfa(user, stepUpCheck(EmailType, "135790")); err != nil {
		t.Fatalf("the email code was rejected: %v", err)
	}
	if err := VerifyEnrolledMfa(user, stepUpCheck(EmailType, "135790")); err == nil {
		t.Fatal("the email code was accepted twice")
	}
}

func TestVerifyEnrolledMfaIsRateLimited(t *testing.T) {
	newStepUpTestDb(t)
	secret := newTestTotpSecret(t)
	user := newStepUpTestUser(t, "limited", secret)
	good := stepUpCheck(TotpType, totpCodeAt(t, secret, pinStepUpClock(t)))

	for i := 0; i < DefaultFailedSigninLimit; i++ {
		if err := VerifyEnrolledMfa(user, stepUpCheck(TotpType, "000000")); err == nil {
			t.Fatal("a wrong code was accepted")
		}
	}

	// the right code is locked out as well, by the per-user limit that the sign-in uses
	err := VerifyEnrolledMfa(user, good)
	if err == nil || !strings.Contains(err.Error(), "too many times") {
		t.Fatalf("the user was not locked out: %v", err)
	}

	// and by the limit of the address, when the limit of the user is cleared
	resetVerifyCodeErrorTimes(user, mfaErrorKey)
	err = VerifyEnrolledMfa(user, good)
	if err == nil || !strings.Contains(err.Error(), "too many times") {
		t.Fatalf("the address was not locked out: %v", err)
	}

	// another address is not locked out by it, only by the user limit that it cleared
	other := *good
	other.ClientIp = "198.51.100.9"
	if err = VerifyEnrolledMfa(user, &other); err != nil {
		t.Fatalf("another address was locked out: %v", err)
	}
}

func TestGetEnrolledMfaPropsReadsTheUser(t *testing.T) {
	user := &User{Owner: "org", Name: "u", Phone: "+15555550100", CountryCode: "US", MfaPhoneEnabled: true, TotpSecret: "SECRET"}

	props, err := GetEnrolledMfaProps(user, SmsType)
	if err != nil || props.Secret != user.Phone || props.CountryCode != "US" {
		t.Fatalf("GetEnrolledMfaProps() = %+v, %v", props, err)
	}
	if _, err = GetEnrolledMfaProps(user, EmailType); err == nil {
		t.Fatal("an email factor that is not enrolled was returned")
	}
}

func TestGenerateMfaProofToken(t *testing.T) {
	newStepUpTestDb(t)
	user := newStepUpTestUser(t, "prover", newTestTotpSecret(t))
	application, err := GetApplicationByClientId(testStepUpClient)
	if err != nil || application == nil {
		t.Fatalf("application: %v, %v", application, err)
	}

	authTime := time.Now().Add(-time.Second).Truncate(time.Second)
	first, err := GenerateMfaProofToken(application, user, TotpType, "approve-payment-42", "n-1", authTime, "localhost:8000")
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateMfaProofToken(application, user, TotpType, "", "", authTime, "localhost:8000")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := getCertByApplication(application)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(cert.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	claims := &MfaProofClaims{}
	if _, err = jwt.ParseWithClaims(first, claims, func(*jwt.Token) (interface{}, error) { return &privateKey.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"})); err != nil {
		t.Fatalf("the proof does not verify with the key of the application: %v", err)
	}

	if claims.Subject != user.Id || claims.Owner != user.Owner || claims.Name != user.Name {
		t.Fatalf("the proof is about %q %s/%s", claims.Subject, claims.Owner, claims.Name)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != testStepUpClient {
		t.Fatalf("the proof is for %v", claims.Audience)
	}
	if strings.Join(claims.Amr, ",") != "mfa,otp" || claims.TokenType != "mfa-proof" {
		t.Fatalf("amr %v, type %s", claims.Amr, claims.TokenType)
	}
	if claims.AuthTime != authTime.Unix() || claims.ExpiresAt.Unix() != authTime.Unix()+MfaProofLifetimeInSeconds {
		t.Fatalf("auth_time %d, exp %v", claims.AuthTime, claims.ExpiresAt)
	}
	if claims.Action != "approve-payment-42" || claims.Nonce != "n-1" {
		t.Fatalf("action %q, nonce %q", claims.Action, claims.Nonce)
	}

	other := &MfaProofClaims{}
	if _, _, err = jwt.NewParser().ParseUnverified(second, other); err != nil {
		t.Fatal(err)
	}
	if other.ID == "" || other.ID == claims.ID {
		t.Fatalf("the jti is not unique: %q and %q", claims.ID, other.ID)
	}

	if _, err = GenerateMfaProofToken(application, user, TotpType, strings.Repeat("a", maxMfaProofClaimSize+1), "", authTime, "localhost"); err == nil {
		t.Fatal("an action that is too long was signed")
	}
}

func TestAddMfaStepUpRecord(t *testing.T) {
	newStepUpTestDb(t)
	user := newStepUpTestUser(t, "audited", newTestTotpSecret(t))
	application, err := GetApplicationByClientId(testStepUpClient)
	if err != nil {
		t.Fatal(err)
	}

	AddMfaStepUpRecord("mfa-verify", user, application, TotpType, "app/"+testStepUpApp, "203.0.113.7", "en", nil)
	AddMfaStepUpRecord("mfa-verify", user, application, TotpType, "app/"+testStepUpApp, "203.0.113.7", "en", errors.New("totp passcode error"))

	records := []*Record{}
	if err = ormer.Engine.Where("organization = ?", testStepUpOrg).Asc("id").Find(&records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Detail != "passed" || records[1].Detail != "failed" {
		t.Fatalf("records: %+v", records)
	}
	for _, field := range []string{user.GetId(), application.GetId(), `"mfaType":"app"`} {
		if !strings.Contains(records[1].Object, field) {
			t.Fatalf("the record misses %s: %s", field, records[1].Object)
		}
	}
	if records[1].User != user.Name || records[1].Action != "mfa-verify" {
		t.Fatalf("record: %+v", records[1])
	}
}
