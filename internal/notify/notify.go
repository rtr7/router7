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

// Package notify implements sending signals (such as SIGUSR1) to processes.
package notify

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var numericRe = regexp.MustCompile(`^[0-9]+$`)

func Process(name string, sig os.Signal) error {
	fis, err := ioutil.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, fi := range fis {
		if !fi.IsDir() {
			continue
		}
		if !numericRe.MatchString(fi.Name()) {
			continue
		}
		b, err := ioutil.ReadFile(filepath.Join("/proc", fi.Name(), "cmdline"))
		if err != nil {
			return err
		}
		if !strings.HasPrefix(string(b), name) {
			continue
		}
		pid, _ := strconv.Atoi(fi.Name()) // already verified to be numeric
		p, _ := os.FindProcess(pid)
		return p.Signal(sig)
	}
	return nil
}
