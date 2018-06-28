// Copyright 2018 Google Inc.
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

package diag_test

import (
	"router7/internal/diag"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDiagLink(t *testing.T) {
	if _, err := diag.Link("nonexistant").Evaluate(); err == nil {
		t.Errorf("Link(nonexistant).Evaluate = nil, want non-nil")
	}

	if _, err := diag.Link("lo").Evaluate(); err != nil {
		t.Errorf("Link(lo).Evaluate = %v, want nil", err)
	}
}

func TestDiagMonitor(t *testing.T) {
	m := diag.NewMonitor(diag.Link("nonexistant").
		Then(diag.DHCPv4()))
	got := m.Evaluate()
	want := &diag.EvalResult{
		Name:   "link/nonexistant",
		Error:  true,
		Status: "Link not found",
		Children: []*diag.EvalResult{
			{
				Name:   "dhcp4",
				Error:  true,
				Status: "dependency link/nonexistant failed",
			},
		},
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("Evaluate(): unexpected result: diff (-got +want):\n%s", diff)
	}
}
