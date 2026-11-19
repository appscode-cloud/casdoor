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
	"path/filepath"
	"testing"
)

// newStepUpTestDb gives the test its own SQLite database, so that it needs no server. Concurrent writers wait
// for each other instead of failing, as they do on a database server.
func newStepUpTestDb(t *testing.T) {
	t.Helper()

	previous := ormer
	adapter, err := NewAdapter("sqlite3", "file:"+filepath.Join(t.TempDir(), "stepup.db")+"?_pragma=busy_timeout(30000)", "")
	if err != nil {
		t.Fatal(err)
	}
	ormer = adapter
	t.Cleanup(func() {
		ormer = previous
		adapter.close()
	})

	for _, table := range []interface{}{new(User), new(Organization), new(Application), new(Provider), new(Cert), new(VerificationRecord), new(Record), new(Webhook), new(Syncer), new(MfaAttempt)} {
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
