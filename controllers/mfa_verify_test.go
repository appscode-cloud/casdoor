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
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestCanApplicationCheckMfaOf(t *testing.T) {
	cases := []struct {
		name        string
		application *object.Application
		user        *object.User
		want        bool
	}{
		{"user of the own organization", &object.Application{Organization: "acme"}, &object.User{Owner: "acme", Name: "alice"}, true},
		{"user of another organization", &object.Application{Organization: "acme"}, &object.User{Owner: "globex", Name: "bob"}, false},
		{"built-in application, user of another organization", &object.Application{Organization: "built-in"}, &object.User{Owner: "globex", Name: "bob"}, false},
		{"built-in application, user of the built-in organization", &object.Application{Organization: "built-in"}, &object.User{Owner: "built-in", Name: "admin"}, true},
		{"application without an organization", &object.Application{}, &object.User{Owner: "", Name: "x"}, false},
		{"no user", &object.Application{Organization: "acme"}, nil, false},
		{"no application", nil, &object.User{Owner: "acme", Name: "alice"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := canApplicationCheckMfaOf(tc.application, tc.user); got != tc.want {
				t.Fatalf("canApplicationCheckMfaOf() = %v, want %v", got, tc.want)
			}
		})
	}
}
