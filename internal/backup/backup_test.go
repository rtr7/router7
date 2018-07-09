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

package backup_test

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rtr7/router7/internal/backup"
)

func TestArchive(t *testing.T) {
	tmpin, err := ioutil.TempDir("", "backuptest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpin)

	if err := ioutil.WriteFile(filepath.Join(tmpin, "random.seed"), []byte{0xaa, 0xbb}, 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(tmpin, "dhcp4d"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := ioutil.WriteFile(filepath.Join(tmpin, "dhcp4d", "leases.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := backup.Archive(&buf, tmpin); err != nil {
		t.Fatal(err)
	}

	tmpout, err := ioutil.TempDir("", "backuptest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpout)
	tar := exec.Command("tar", "xzf", "-", "-C", tmpout)
	tar.Stdin = &buf
	tar.Stderr = os.Stderr
	if err := tar.Run(); err != nil {
		t.Fatal(err)
	}

	diff := exec.Command("diff", "-ur", tmpin, tmpout)
	diff.Stdout = os.Stdout
	diff.Stderr = os.Stderr
	if err := diff.Run(); err != nil {
		t.Fatal(err)
	}
}
