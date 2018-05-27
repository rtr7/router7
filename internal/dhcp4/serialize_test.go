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
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("unexpected config: diff (-got +want):\n%s", diff)
	}
}
