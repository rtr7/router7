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

package dhcp4

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestSerialize(t *testing.T) {
	want := Config{
		RenewAfter: time.Now().Add(30 * time.Minute),
		ClientIP:   "85.195.207.62",
		SubnetMask: "255.255.255.128",
		Router:     "85.195.207.1",
		DNS: []string{
			"77.109.128.2",
			"213.144.129.20",
		},
	}
	// Round-trip through JSON to verify serialization works
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(b))
	var got Config
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected config: diff (-want +got):\n%s", diff)
	}
}
