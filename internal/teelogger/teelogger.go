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

type nonBlockingWriter struct {
	W chan<- string
}

func (w *nonBlockingWriter) Write(p []byte) (n int, _ error) {
	select {
	// Intentionally convert from byte slice ([]byte) to string because sending
	// a byte slice over a channel is not safe: it may point to new contents,
	// resulting in duplicate log lines showing up.
	case w.W <- string(p):
	default:
		// channel unavailable, ignore
	}
	return len(p), nil
}

// NewConsole returns a logger which returns to /dev/console and
// os.Stderr. Writes to /dev/console are non-blocking, i.e. messages will be
// discarded if /dev/console stalls (e.g. when enabling Scroll Lock on a HDMI
// console).
func NewConsole() *log.Logger {
	w := ioutil.Discard
	if console, err := os.OpenFile("/dev/console", os.O_RDWR, 0600); err == nil {
		ch := make(chan string, 1)
		go func() {
			for buf := range ch {
				console.Write([]byte(buf))
			}
		}()
		w = &nonBlockingWriter{W: ch}
	}
	return log.New(io.MultiWriter(os.Stderr, w), "", log.LstdFlags|log.Lshortfile)
}
