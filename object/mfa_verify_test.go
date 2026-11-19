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
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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

func newStepUpTestUser(t *testing.T, name string, totpSecret string) *User {
	t.Helper()

	user := &User{
		Owner: testStepUpOrg, Name: name, Id: util.GenerateUUID(), SignupApplication: testStepUpApp,
		TotpSecret: totpSecret, PreferredMfaType: TotpType, RecoveryCodes: []string{"recovery-1", "recovery-2"},
	}
	insertStepUpRows(t, user)
	return user
}

func getStoredStepUpUser(t *testing.T, user *User) *User {
	t.Helper()

	stored, err := getUser(user.Owner, user.Name)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func newTestTotpSecret(t *testing.T) string {
	t.Helper()

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test", AccountName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return key.Secret()
}

func totpCodeAtPeriod(t *testing.T, secret string, at time.Time, period uint) string {
	t.Helper()

	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: period, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func totpCodeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	return totpCodeAtPeriod(t, secret, at, MfaTotpPeriodInSeconds)
}

// setStepUpClock sets the clock of the codes
func setStepUpClock(t *testing.T, now time.Time) {
	t.Helper()

	mfaStepUpNow = func() time.Time { return now }
	t.Cleanup(func() { mfaStepUpNow = time.Now })
}

// pinStepUpClock keeps a test from straddling a time step
func pinStepUpClock(t *testing.T) time.Time {
	t.Helper()

	now := time.Now()
	setStepUpClock(t, now)
	return now
}

func stepUpCheck(mfaType string, passcode string) *MfaStepUpCheck {
	return &MfaStepUpCheck{MfaType: mfaType, Passcode: passcode, ClientIp: "203.0.113.7", Lang: "en"}
}

func requireMfaOutcome(t *testing.T, err error, outcome string) {
	t.Helper()

	if err == nil {
		t.Fatalf("passed, want the outcome %s", outcome)
	}
	if got := GetMfaOutcome(err); got != outcome {
		t.Fatalf("the outcome is %q, want %q: %v", got, outcome, err)
	}
}

func TestMatchTotpCode(t *testing.T) {
	secret := newTestTotpSecret(t)
	now := time.Unix(1_800_000_000, 0)
	currentStart := now.Unix() / MfaTotpPeriodInSeconds * MfaTotpPeriodInSeconds

	cases := []struct {
		name     string
		at       time.Time
		wantTime int64
		wantOk   bool
	}{
		{"current step", now, currentStart, true},
		{"previous step", now.Add(-30 * time.Second), currentStart - 30, true},
		{"next step", now.Add(30 * time.Second), currentStart + 30, true},
		{"two steps back", now.Add(-60 * time.Second), 0, false},
		{"two steps ahead", now.Add(60 * time.Second), 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stepTime, ok := matchTotpCode(secret, totpCodeAt(t, secret, tc.at), now)
			if ok != tc.wantOk || stepTime != tc.wantTime {
				t.Fatalf("matchTotpCode() = (%d, %v), want (%d, %v)", stepTime, ok, tc.wantTime, tc.wantOk)
			}
		})
	}

	if _, ok := matchTotpCode(secret, "12345", now); ok {
		t.Fatal("a passcode of the wrong length was accepted")
	}
	if _, ok := matchTotpCode(secret, "", now); ok {
		t.Fatal("an empty passcode was accepted")
	}

	// a 60 s token: the time is in seconds whatever the period
	stepTime, ok := matchTotpCode(secret+"?period=60", totpCodeAtPeriod(t, secret, now, 60), now)
	if !ok || stepTime != now.Unix()/60*60 {
		t.Fatalf("matchTotpCode() of a 60 s token = (%d, %v)", stepTime, ok)
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
	requireMfaOutcome(t, VerifyEnrolledMfa(user, stepUpCheck(TotpType, current)), MfaOutcomeWrongCode)
	requireMfaOutcome(t, VerifyEnrolledMfa(user, stepUpCheck(TotpType, previous)), MfaOutcomeWrongCode)
	if err := VerifyEnrolledMfa(user, stepUpCheck(TotpType, next)); err != nil {
		t.Fatalf("a code of a later step was rejected: %v", err)
	}
	requireMfaOutcome(t, VerifyEnrolledMfa(user, stepUpCheck(TotpType, next)), MfaOutcomeWrongCode)

	if want := now.Add(30*time.Second).Unix() / MfaTotpPeriodInSeconds * MfaTotpPeriodInSeconds; getStoredStepUpUser(t, user).MfaTotpLastTime != want {
		t.Fatalf("the stored time is %d, want %d", getStoredStepUpUser(t, user).MfaTotpLastTime, want)
	}
}

// Finding 3 of the review: the sign-in and the RADIUS server did not read or advance the replay guard
func TestTotpCodeWorksOnceAcrossSigninAndStepUp(t *testing.T) {
	newStepUpTestDb(t)
	secret := newTestTotpSecret(t)
	user := newStepUpTestUser(t, "replay2", secret)
	now := pinStepUpClock(t)
	current := totpCodeAt(t, secret, now)
	next := totpCodeAt(t, secret, now.Add(30*time.Second))

	// the code typed at the sign-in (controllers/auth.go) or on the RADIUS server
	signin := GetMfaUtil(TotpType, user.GetMfaProps(TotpType, false))
	if err := VerifyUserMfaPasscode(user, signin, current, "en"); err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	requireMfaOutcome(t, VerifyEnrolledMfa(user, stepUpCheck(TotpType, current)), MfaOutcomeWrongCode)

	if err := VerifyEnrolledMfa(user, stepUpCheck(TotpType, next)); err != nil {
		t.Fatal(err)
	}
	requireMfaOutcome(t, VerifyUserMfaPasscode(user, signin, next, "en"), MfaOutcomeWrongCode)
}

func TestVerifyEnrolledMfaChecksOnlyTheEnrolledFactor(t *testing.T) {
	newStepUpTestDb(t)
	secret := newTestTotpSecret(t)
	user := newStepUpTestUser(t, "enrolled", secret)
	code := totpCodeAt(t, secret, pinStepUpClock(t))

	for _, mfaType := range []string{EmailType, SmsType, "", "unknown"} {
		if err := VerifyEnrolledMfa(user, stepUpCheck(mfaType, code)); err == nil {
			t.Fatalf("a valid TOTP code passed as the type %q that the user has not enrolled", mfaType)
		}
	}
	requireMfaOutcome(t, VerifyEnrolledMfa(user, stepUpCheck(EmailType, code)), MfaOutcomeNotEnrolled)

	// a failed check of another type must not have used the code
	if err := VerifyEnrolledMfa(user, stepUpCheck(TotpType, code)); err != nil {
		t.Fatalf("the enrolled factor was rejected: %v", err)
	}
}

// Finding 1 of the review: whoever asks for a push can approve it, a RADIUS code may work twice
func TestVerifyEnrolledMfaRefusesPushAndRadius(t *testing.T) {
	newStepUpTestDb(t)
	user := newStepUpTestUser(t, "pusher", "")
	user.MfaPushEnabled, user.MfaPushReceiver, user.MfaPushProvider = true, "victim-device", "admin/notify"
	user.MfaRadiusEnabled, user.MfaRadiusUsername, user.MfaRadiusProvider = true, "radius-user", "admin/radius"
	if _, err := ormer.Engine.ID([]interface{}{user.Owner, user.Name}).Cols("mfa_push_enabled", "mfa_push_receiver", "mfa_push_provider", "mfa_radius_enabled", "mfa_radius_username", "mfa_radius_provider").Update(user); err != nil {
		t.Fatal(err)
	}

	challenge := &PushChallenge{Id: "chal-1", UserId: user.GetId(), Purpose: PushPurposeSignin, Provider: "admin/notify", Receiver: "victim-device", Status: PushChallengeApproved, CreatedTime: time.Now()}
	pushChallenges.Store(challenge.Id, challenge)
	t.Cleanup(func() { pushChallenges.Delete(challenge.Id) })

	for _, mfaType := range []string{PushType, RadiusType} {
		requireMfaOutcome(t, VerifyEnrolledMfa(user, stepUpCheck(mfaType, challenge.Id)), MfaOutcomeBadRequest)
	}
	if _, err := GetMfaStepUpDest(user, PushType); err == nil {
		t.Fatal("a push destination was returned for a step-up check")
	}
}

func TestVerifyEnrolledMfaRejectsTheMasterVerificationCode(t *testing.T) {
	newStepUpTestDb(t)
	secret := newTestTotpSecret(t)
	user := newStepUpTestUser(t, "master", secret)

	if _, ok := matchTotpCode(secret, testMasterCode, pinStepUpClock(t)); ok {
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
	requireMfaOutcome(t, VerifyEnrolledMfa(user, check), MfaOutcomeWrongCode)

	stored := getStoredStepUpUser(t, user)
	if len(stored.RecoveryCodes) != 1 || stored.RecoveryCodes[0] != "recovery-2" {
		t.Fatalf("the other recovery codes were changed: %v", stored.RecoveryCodes)
	}

	both := &MfaStepUpCheck{RecoveryCode: "recovery-2", Passcode: "123456", ClientIp: "203.0.113.7", Lang: "en"}
	requireMfaOutcome(t, VerifyEnrolledMfa(user, both), MfaOutcomeBadRequest)
}

// Finding 6 of the review: the sign-in wrote back the copy of the user it loaded at the start of the request
func TestRecoveryCodeStaleCopyDoesNotBringItBack(t *testing.T) {
	newStepUpTestDb(t)
	user := newStepUpTestUser(t, "lost", newTestTotpSecret(t))

	stale := getStoredStepUpUser(t, user)
	if err := VerifyEnrolledMfa(user, &MfaStepUpCheck{RecoveryCode: "recovery-1", ClientIp: "203.0.113.7", Lang: "en"}); err != nil {
		t.Fatal(err)
	}
	// the concurrent sign-in with the other code, controllers/auth.go -> object.MfaRecover(user, ...)
	if err := MfaRecover(stale, "recovery-2"); err != nil {
		t.Fatal(err)
	}
	if err := MfaRecover(stale, "recovery-1"); err == nil {
		t.Fatal("a used recovery code was accepted again through a stale copy of the user")
	}
	requireMfaOutcome(t, VerifyEnrolledMfa(user, &MfaStepUpCheck{RecoveryCode: "recovery-1", ClientIp: "203.0.113.7", Lang: "en"}), MfaOutcomeWrongCode)
	if codes := getStoredStepUpUser(t, user).RecoveryCodes; len(codes) != 0 {
		t.Fatalf("recovery codes left: %v", codes)
	}
}

func TestRecoveryCodeWorksOnceUnderConcurrency(t *testing.T) {
	newStepUpTestDb(t)
	user := newStepUpTestUser(t, "racer", newTestTotpSecret(t))

	const n = 8
	var wg sync.WaitGroup
	var passed atomic.Int64
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if MfaRecover(&User{Owner: user.Owner, Name: user.Name}, "recovery-1") == nil {
				passed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if passed.Load() != 1 {
		t.Fatalf("one recovery code passed %d times", passed.Load())
	}
	if codes := getStoredStepUpUser(t, user).RecoveryCodes; len(codes) != 1 || codes[0] != "recovery-2" {
		t.Fatalf("recovery codes left: %v", codes)
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

	requireMfaOutcome(t, VerifyEnrolledMfa(user, stepUpCheck(EmailType, "000000")), MfaOutcomeWrongCode)
	if err := VerifyEnrolledMfa(user, stepUpCheck(EmailType, "135790")); err != nil {
		t.Fatalf("the email code was rejected: %v", err)
	}
	requireMfaOutcome(t, VerifyEnrolledMfa(user, stepUpCheck(EmailType, "135790")), MfaOutcomeWrongCode)
}

// Finding 6 of the review: the code was checked, then marked used in another step
func TestUseVerificationCodeWorksOnceUnderConcurrency(t *testing.T) {
	newStepUpTestDb(t)
	organization := &Organization{Name: testStepUpOrg}
	if err := AddToVerificationRecord(nil, &Provider{Name: "mailer"}, organization, "203.0.113.7", "Email", "racer@example.com", "246802"); err != nil {
		t.Fatal(err)
	}

	const n = 8
	var wg sync.WaitGroup
	var passed atomic.Int64
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, err := UseVerificationCode("racer@example.com", "246802", "en")
			if err == nil && result.Code == VerificationSuccess {
				passed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if passed.Load() != 1 {
		t.Fatalf("one code passed %d times", passed.Load())
	}
}

func TestVerifyEnrolledMfaIsRateLimited(t *testing.T) {
	newStepUpTestDb(t)
	secret := newTestTotpSecret(t)
	user := newStepUpTestUser(t, "limited", secret)
	good := stepUpCheck(TotpType, totpCodeAt(t, secret, pinStepUpClock(t)))

	for i := 0; i < DefaultFailedSigninLimit; i++ {
		err := VerifyEnrolledMfa(user, stepUpCheck(TotpType, "000000"))
		requireMfaOutcome(t, err, MfaOutcomeWrongCode)
		if want := fmt.Sprintf("you have %d remaining chances", DefaultFailedSigninLimit-1-i); !strings.Contains(err.Error(), want) {
			t.Fatalf("the error %q does not say %q", err, want)
		}
	}

	// the right code is locked out as well, by the per-user limit that the sign-in uses
	err := VerifyEnrolledMfa(user, good)
	requireMfaOutcome(t, err, MfaOutcomeRateLimited)
	if !strings.Contains(err.Error(), "too many times") {
		t.Fatalf("the user was not locked out: %v", err)
	}

	// and by the limit of the address, when the limit of the user is cleared
	if err = resetMfaUserLimit(user); err != nil {
		t.Fatal(err)
	}
	requireMfaOutcome(t, VerifyEnrolledMfa(user, good), MfaOutcomeRateLimited)

	// another address is not locked out by it, only by the user limit that it cleared
	other := *good
	other.ClientIp = "198.51.100.9"
	if err = VerifyEnrolledMfa(user, &other); err != nil {
		t.Fatalf("another address was locked out: %v", err)
	}
}

func TestMfaLimitLiftsAfterTheWindow(t *testing.T) {
	newStepUpTestDb(t)
	secret := newTestTotpSecret(t)
	user := newStepUpTestUser(t, "window", secret)
	now := pinStepUpClock(t)
	mfaAttemptNow = func() time.Time { return now }
	t.Cleanup(func() { mfaAttemptNow = time.Now })

	for i := 0; i < DefaultFailedSigninLimit; i++ {
		_ = VerifyMfaWithLimit(user, func() error { return NewMfaError(MfaOutcomeWrongCode, "totp passcode error") }, "en")
	}
	requireMfaOutcome(t, VerifyMfaWithLimit(user, func() error { return nil }, "en"), MfaOutcomeRateLimited)

	// the refused tries are not kept, the lock lifts when the failures leave the window
	mfaAttemptNow = func() time.Time { return now.Add(DefaultFailedSigninFrozenTime*time.Minute + time.Second) }
	if err := VerifyMfaWithLimit(user, func() error { return nil }, "en"); err != nil {
		t.Fatalf("the lock did not lift: %v", err)
	}
}

// Finding 4 of the review: a burst of concurrent wrong codes got 20 to 196 codes evaluated against a limit of 5
func TestMfaLimitHoldsUnderABurst(t *testing.T) {
	newStepUpTestDb(t)
	secret := newTestTotpSecret(t)
	user := newStepUpTestUser(t, "burst", secret)
	pinStepUpClock(t)

	const n = 100
	var wg sync.WaitGroup
	var evaluated, limited, other atomic.Int64
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			err := VerifyMfaWithLimit(user, func() error {
				evaluated.Add(1)
				return NewMfaError(MfaOutcomeWrongCode, fmt.Sprintf("totp passcode error %d", i))
			}, "en")
			switch GetMfaOutcome(err) {
			case MfaOutcomeWrongCode:
			case MfaOutcomeRateLimited:
				limited.Add(1)
			default:
				other.Add(1)
				t.Errorf("unexpected error: %v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if evaluated.Load() > DefaultFailedSigninLimit || evaluated.Load() == 0 || evaluated.Load()+limited.Load() != n {
		t.Fatalf("a burst of %d codes got %d evaluated and %d refused, the limit is %d", n, evaluated.Load(), limited.Load(), DefaultFailedSigninLimit)
	}
}

// a setup verification passes a code of the new factor: it must not forget the failures of the enrolled one
func TestVerifyMfaSetupWithLimitKeepsTheFailures(t *testing.T) {
	newStepUpTestDb(t)
	user := newStepUpTestUser(t, "setup", newTestTotpSecret(t))

	for i := 0; i < DefaultFailedSigninLimit-1; i++ {
		_ = VerifyMfaWithLimit(user, func() error { return NewMfaError(MfaOutcomeWrongCode, "totp passcode error") }, "en")
	}
	if err := VerifyMfaSetupWithLimit(user, func() error { return nil }, "en"); err != nil {
		t.Fatal(err)
	}
	_ = VerifyMfaWithLimit(user, func() error { return NewMfaError(MfaOutcomeWrongCode, "totp passcode error") }, "en")
	requireMfaOutcome(t, VerifyMfaWithLimit(user, func() error { return nil }, "en"), MfaOutcomeRateLimited)
}

// Finding 8 of the review: the step of a 30 s token blocked a token with another period
func TestTotpPeriodChangeDoesNotLockOut(t *testing.T) {
	newStepUpTestDb(t)
	secret := newTestTotpSecret(t)
	user := newStepUpTestUser(t, "period", secret)
	now := pinStepUpClock(t)

	if err := VerifyEnrolledMfa(user, stepUpCheck(TotpType, totpCodeAt(t, secret, now))); err != nil {
		t.Fatal(err)
	}

	// an imported 60 s hardware token, written without going through the setup (see otp_token.go)
	user.TotpSecret = secret + "?period=60"
	if _, err := ormer.Engine.ID([]interface{}{user.Owner, user.Name}).Cols("totp_secret").Update(user); err != nil {
		t.Fatal(err)
	}
	later := now.Add(5 * time.Minute)
	setStepUpClock(t, later)
	if err := VerifyEnrolledMfa(user, stepUpCheck(TotpType, totpCodeAtPeriod(t, secret, later, 60))); err != nil {
		t.Fatalf("a valid 60 s code five minutes later was refused: %v", err)
	}

	// and a new secret set up starts without a used code
	mfa := NewTotpMfaUtil(&MfaProps{MfaType: TotpType, Secret: newTestTotpSecret(t)})
	if err := mfa.Enable(user); err != nil {
		t.Fatal(err)
	}
	if stored := getStoredStepUpUser(t, user); stored.MfaTotpLastTime != 0 || stored.TotpSecret != mfa.Secret {
		t.Fatalf("after a new secret, the stored time is %d", stored.MfaTotpLastTime)
	}
}

// Finding 9 of the review: a full update restored the replay guard from a copy read before
func TestUpdateUserForAllFieldsKeepsTheReplayGuard(t *testing.T) {
	newStepUpTestDb(t)
	secret := newTestTotpSecret(t)
	user := newStepUpTestUser(t, "full", secret)
	now := pinStepUpClock(t)

	stale := getStoredStepUpUser(t, user)
	if err := VerifyEnrolledMfa(user, stepUpCheck(TotpType, totpCodeAt(t, secret, now))); err != nil {
		t.Fatal(err)
	}
	claimed := getStoredStepUpUser(t, user).MfaTotpLastTime

	stale.DisplayName = "renamed"
	if _, err := UpdateUserForAllFields(stale.GetId(), stale); err != nil {
		t.Fatal(err)
	}
	stored := getStoredStepUpUser(t, user)
	if stored.DisplayName != "renamed" || stored.MfaTotpLastTime != claimed {
		t.Fatalf("display name %q, stored time %d, want %d", stored.DisplayName, stored.MfaTotpLastTime, claimed)
	}
}

func TestGetEnrolledMfaPropsReadsTheUser(t *testing.T) {
	user := &User{Owner: "org", Name: "u", Phone: "+15555550100", CountryCode: "US", MfaPhoneEnabled: true, TotpSecret: "SECRET"}

	props, err := GetEnrolledMfaProps(user, SmsType)
	if err != nil || props.Secret != user.Phone || props.CountryCode != "US" {
		t.Fatalf("GetEnrolledMfaProps() = %+v, %v", props, err)
	}
	if _, err = GetEnrolledMfaProps(user, EmailType); GetMfaOutcome(err) != MfaOutcomeNotEnrolled {
		t.Fatalf("an email factor that is not enrolled: %v", err)
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
	token, err := jwt.ParseWithClaims(first, claims, func(*jwt.Token) (interface{}, error) { return &privateKey.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("the proof does not verify with the key of the application: %v", err)
	}

	// finding 5 of the review: nothing but "typ" told the proof from an access token of the user
	if token.Header["typ"] != MfaProofTokenType {
		t.Fatalf("the typ header is %v", token.Header["typ"])
	}
	raw := map[string]interface{}{}
	if _, _, err = jwt.NewParser().ParseUnverified(first, jwt.MapClaims(raw)); err != nil {
		t.Fatal(err)
	}
	for _, claim := range []string{"owner", "name"} {
		if _, ok := raw[claim]; ok {
			t.Fatalf("the proof has the %q claim of an access token", claim)
		}
	}

	if claims.Subject != user.Id {
		t.Fatalf("the proof is about %q", claims.Subject)
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
}

// Finding 7 of the review: a proof that can't be signed was refused only after the code was used up
func TestMfaProofSignerIsReadyBeforeTheCheck(t *testing.T) {
	newStepUpTestDb(t)
	user := newStepUpTestUser(t, "signer", newTestTotpSecret(t))
	application, err := GetApplicationByClientId(testStepUpClient)
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewMfaProofSigner(application, user, strings.Repeat("a", maxMfaProofClaimSize+1), "", "localhost")
	requireMfaOutcome(t, err, MfaOutcomeBadRequest)

	application.Cert = "no-such-cert"
	if _, err = NewMfaProofSigner(application, user, "", "", "localhost"); err == nil {
		t.Fatal("a proof was prepared without a certificate")
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

// Finding 1 of the review: the id that the page asking for a push holds also approved it
func TestPushChallengeNeedsTheApprovalToken(t *testing.T) {
	challenge := &PushChallenge{
		Id: "chal-2", UserId: "org/alice", Purpose: PushPurposeSignin, Provider: "admin/notify", Receiver: "phone-1",
		Status: PushChallengePending, CreatedTime: time.Now(), approvalToken: "token-2",
	}
	pushChallenges.Store(challenge.Id, challenge)
	pushApprovals.Store(challenge.approvalToken, challenge.Id)
	t.Cleanup(func() { deletePushChallenge(challenge) })

	if _, err := AnswerPushChallenge(challenge.Id, true); err == nil {
		t.Fatal("the push was approved with the id of the page asking for it")
	}
	if got := GetPushChallenge(challenge.Id); got == nil || got.approvalToken != "" || got.Status != PushChallengePending {
		t.Fatalf("the challenge for the page polling: %+v", got)
	}
	if got := GetPushChallenge(challenge.approvalToken); got == nil || got.Id != challenge.Id {
		t.Fatalf("the challenge for the confirmation page: %+v", got)
	}

	if _, err := AnswerPushChallenge(challenge.approvalToken, true); err != nil {
		t.Fatal(err)
	}
	// bound to the user and the purpose
	if err := consumePushChallenge(challenge.Id, "admin/notify", "phone-1", "org/mallory", PushPurposeSignin); err == nil {
		t.Fatal("the push of another user was accepted")
	}
	if err := consumePushChallenge(challenge.Id, "admin/notify", "phone-1", "org/alice", PushPurposeSetup); err == nil {
		t.Fatal("the push of a sign-in was accepted for a setup")
	}
	if err := consumePushChallenge(challenge.Id, "admin/notify", "phone-1", "org/alice", PushPurposeSignin); err != nil {
		t.Fatal(err)
	}
	if err := consumePushChallenge(challenge.Id, "admin/notify", "phone-1", "org/alice", PushPurposeSignin); err == nil {
		t.Fatal("an approved push worked twice")
	}
	if GetPushChallenge(challenge.approvalToken) != nil {
		t.Fatal("the approval token outlived the push")
	}
}

func TestPushChallengeIsConsumedOnceUnderConcurrency(t *testing.T) {
	challenge := &PushChallenge{
		Id: "chal-3", UserId: "org/alice", Purpose: PushPurposeSignin, Provider: "admin/notify", Receiver: "phone-1",
		Status: PushChallengeApproved, CreatedTime: time.Now(), approvalToken: "token-3",
	}
	pushChallenges.Store(challenge.Id, challenge)
	pushApprovals.Store(challenge.approvalToken, challenge.Id)
	t.Cleanup(func() { deletePushChallenge(challenge) })

	const n = 16
	var wg sync.WaitGroup
	var passed atomic.Int64
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if consumePushChallenge(challenge.Id, "admin/notify", "phone-1", "org/alice", PushPurposeSignin) == nil {
				passed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if passed.Load() != 1 {
		t.Fatalf("one approved push passed %d times", passed.Load())
	}
}
