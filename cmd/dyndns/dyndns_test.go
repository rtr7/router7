package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/libdns/libdns"
	"github.com/rtr7/router7/internal/dyndns"
)

func TestLogic(t *testing.T) {
	cfg := DynDNSRecord{
		Zone:             "zekjur.net",
		RecordName:       "dyndns.zekjur.net",
		RecordTTLSeconds: 300, // 5 minutes
	}
	update = func(ctx context.Context, zone string, record libdns.Record, _ dyndns.RecordGetterSetter) error {
		if got, want := zone, cfg.Zone; got != want {
			return fmt.Errorf("update(): unexpected zone: got %q, want %q", got, want)
		}
		if got, want := record.Name, cfg.RecordName; got != want {
			return fmt.Errorf("update(): unexpected record name: got %q, want %q", got, want)
		}
		return nil
	}
	if err := logic("lo", []DynDNSRecord{cfg}); err != nil {
		t.Fatalf("logic: %v", err)
	}

}
