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
