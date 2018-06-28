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

// Package diag implements network diagnostics.
package diag

import "fmt"

type Node interface {
	Then(t Node) Node
	Children() []Node
	Evaluate() (status string, _ error)
}

type Monitor struct {
	root Node
}

func NewMonitor(n Node) *Monitor {
	return &Monitor{root: n}
}

type EvalResult struct {
	Name     string
	Error    bool
	Status   string
	Children []*EvalResult
}

func evaluate(n Node, err string) *EvalResult {
	r := EvalResult{
		Name:   fmt.Sprintf("%s", n),
		Status: err,
		Error:  err != "",
	}
	if r.Status == "" {
		status, err := n.Evaluate()
		if err != nil {
			r.Error = true
			r.Status = err.Error()
		} else {
			r.Status = status
		}
	}
	var childErr string
	if r.Error {
		childErr = fmt.Sprintf("dependency %s failed", r.Name)
	}
	for _, n := range n.Children() {
		r.Children = append(r.Children, evaluate(n, childErr))
	}
	return &r
}

func (m *Monitor) Evaluate() *EvalResult {
	return evaluate(m.root, "")
}
