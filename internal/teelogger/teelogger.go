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

// Package teelogger provides loggers which send their output to multiple
// writers, like the tee(1) command.
package teelogger

import (
	"io"
	"io/ioutil"
	"log"
	"os"
)

// NewConsole returns a logger which returns to /dev/console and os.Stderr.
func NewConsole() *log.Logger {
	var w io.Writer
	w, err := os.OpenFile("/dev/console", os.O_RDWR, 0600)
	if err != nil {
		w = ioutil.Discard
	}
	return log.New(io.MultiWriter(os.Stderr, w), "", log.LstdFlags|log.Lshortfile)
}
