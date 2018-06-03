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
