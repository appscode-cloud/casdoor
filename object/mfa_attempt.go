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
	"strconv"
	"sync/atomic"
	"time"

	"github.com/casdoor/casdoor/i18n"
)

// MfaAttempt is one try of a second factor that counts against a limit. It is written before the factor
// is checked and counted after it is written, in the database: of many concurrent tries only as many as
// the limit allows find themselves within it, and every replica of Casdoor counts the same tries. A
// failed try stays as the failure, a passed one is taken back.
type MfaAttempt struct {
	Id          int64  `xorm:"pk autoincr" json:"id"`
	LimitKey    string `xorm:"varchar(300) notnull index" json:"limitKey"`
	CreatedTime int64  `xorm:"bigint notnull index" json:"createdTime"`
}

// mfaLimit allows Max tries under Key within Window
type mfaLimit struct {
	Key    string
	Max    int
	Window time.Duration
}

// mfaAttemptRetention is how long a try is kept at most, longer than any window
const mfaAttemptRetention = 7 * 24 * time.Hour

// mfaAttemptNow is replaced by the tests
var mfaAttemptNow = time.Now

var mfaAttemptCount atomic.Uint64

// getMfaUserLimit is the limit of the failed MFA codes of a user, shared by the sign-in, the step-up check and
// the setup, with the failed sign-in settings of the user's application
func getMfaUserLimit(user *User) (mfaLimit, error) {
	failedSigninLimit, failedSigninFrozenTime, err := GetFailedSigninConfigByUser(user)
	if err != nil {
		return mfaLimit{}, err
	}
	return mfaLimit{Key: "mfa:" + user.GetId(), Max: failedSigninLimit, Window: time.Duration(failedSigninFrozenTime) * time.Minute}, nil
}

// getMfaStepUpIpLimit is the limit of one client address checking the factors of one user: a backend that
// checks the codes of many users is not locked out by one of them
func getMfaStepUpIpLimit(user *User, clientIp string) mfaLimit {
	return mfaLimit{Key: "mfa-step-up:" + clientIp + ":" + user.GetId(), Max: defaultVerifyCodeIpLimit, Window: defaultVerifyCodeIpFrozenMinute * time.Minute}
}

type mfaAttemptReservation struct {
	ids       []int64
	limits    []mfaLimit
	remaining int
}

func getMfaTooManyTimesError(lang string, minutes int) error {
	return newMfaError(MfaOutcomeRateLimited, fmt.Errorf(i18n.Translate(lang, "check:You have entered the wrong password or code too many times, please wait for %d minutes and try again"), minutes))
}

// reserveMfaAttempt writes a try under every limit, then counts the tries within each window: over a limit the
// try is taken back and refused, so that refused tries don't keep the limit from lifting
func reserveMfaAttempt(limits []mfaLimit, lang string) (*mfaAttemptReservation, error) {
	now := mfaAttemptNow()
	sweepMfaAttempts(now)

	reservation := &mfaAttemptReservation{limits: limits, remaining: -1}
	for _, limit := range limits {
		attempt := &MfaAttempt{LimitKey: limit.Key, CreatedTime: now.UnixMilli()}
		if _, err := ormer.Engine.Insert(attempt); err != nil {
			reservation.undo()
			return nil, err
		}
		reservation.ids = append(reservation.ids, attempt.Id)
	}

	for _, limit := range limits {
		since := now.Add(-limit.Window).UnixMilli()
		count, err := ormer.Engine.Where("limit_key = ? AND created_time > ?", limit.Key, since).Count(&MfaAttempt{})
		if err != nil {
			reservation.undo()
			return nil, err
		}
		if count > int64(limit.Max) {
			reservation.undo()
			return nil, getMfaTooManyTimesError(lang, getMfaLimitMinutesLeft(limit, now))
		}
		if left := limit.Max - int(count); reservation.remaining < 0 || left < reservation.remaining {
			reservation.remaining = left
		}
	}
	return reservation, nil
}

// getMfaLimitMinutesLeft is how long until the oldest try within the window leaves it
func getMfaLimitMinutesLeft(limit mfaLimit, now time.Time) int {
	attempt := &MfaAttempt{}
	has, err := ormer.Engine.Where("limit_key = ? AND created_time > ?", limit.Key, now.Add(-limit.Window).UnixMilli()).Asc("created_time").Get(attempt)
	if err != nil || !has {
		return int(limit.Window.Minutes())
	}
	left := time.UnixMilli(attempt.CreatedTime).Add(limit.Window).Sub(now)
	minutes := int((left + time.Minute - 1) / time.Minute)
	if minutes < 1 {
		minutes = 1
	}
	return minutes
}

func (reservation *mfaAttemptReservation) undo() {
	for _, id := range reservation.ids {
		_, _ = ormer.Engine.ID(id).Delete(&MfaAttempt{})
	}
	reservation.ids = nil
}

// failed keeps the try as a failure and adds the chances that are left to the error of the check
func (reservation *mfaAttemptReservation) failed(err error, lang string) error {
	if reservation.remaining < 0 {
		return err
	}

	limitErr := fmt.Errorf(i18n.Translate(lang, "check:password or code is incorrect, you have %s remaining chances"), strconv.Itoa(reservation.remaining))
	msg := fmt.Errorf("%s, %s", err.Error(), limitErr.Error())
	var mfaErr *MfaError
	if errors.As(err, &mfaErr) {
		return newMfaError(mfaErr.Outcome, msg)
	}
	return msg
}

// passed takes the try back, and with reset forgets the failures under its limits as well
func (reservation *mfaAttemptReservation) passed(reset bool) {
	reservation.undo()
	if !reset {
		return
	}
	for _, limit := range reservation.limits {
		_, _ = ormer.Engine.Where("limit_key = ?", limit.Key).Delete(&MfaAttempt{})
	}
}

// sweepMfaAttempts deletes the tries older than any window, now and then
func sweepMfaAttempts(now time.Time) {
	if mfaAttemptCount.Add(1)%500 != 1 {
		return
	}
	_, _ = ormer.Engine.Where("created_time < ?", now.Add(-mfaAttemptRetention).UnixMilli()).Delete(&MfaAttempt{})
}

// verifyMfaWithLimits checks a factor of the user against the per-user MFA limit and the extra limits: the try is
// reserved first and kept only when the check fails. resetOnPass forgets the earlier failures after a pass.
func verifyMfaWithLimits(user *User, extra []mfaLimit, verify func() error, resetOnPass bool, lang string) error {
	userLimit, err := getMfaUserLimit(user)
	if err != nil {
		return err
	}

	reservation, err := reserveMfaAttempt(append([]mfaLimit{userLimit}, extra...), lang)
	if err != nil {
		return err
	}

	err = verify()
	if err != nil {
		return reservation.failed(err, lang)
	}

	reservation.passed(resetOnPass)
	return nil
}

// resetMfaUserLimit forgets the failed MFA codes of the user
func resetMfaUserLimit(user *User) error {
	_, err := ormer.Engine.Where("limit_key = ?", "mfa:"+user.GetId()).Delete(&MfaAttempt{})
	return err
}
