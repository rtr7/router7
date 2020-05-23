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

package dyndns

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestUpdate(t *testing.T) {
	ctx, canc := context.WithCancel(context.Background())
	defer canc()

	const zone = "zekjur.net"
	provider := &testProvider{
		getRecords: func(ctx context.Context, zone string) ([]libdns.Record, error) {
			return []libdns.Record{
				{
					ID:    "rec1",
					Name:  "dyndns.zekjur.net",
					Type:  "A",
					TTL:   5 * time.Minute,
					Value: "127.0.0.3",
				},

				{
					ID:    "rec1",
					Name:  "unrelated.zekjur.net",
					Type:  "A",
					TTL:   5 * time.Minute,
					Value: "127.0.0.42",
				},
			}, nil
		},
		setRecords: func(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
			log.Printf("setRecords(zone=%q): %+v", zone, recs)
			// Don't care about return records?
			return nil, nil
		},
	}
	update := libdns.Record{
		Name:  "dyndns.zekjur.net",
		Type:  "A",
		Value: "127.0.0.4",
		TTL:   5 * time.Minute,
	}
	if err := Update(ctx, zone, update, provider); err != nil {
		t.Fatalf("Update = %v", err)
	}

	// TODO: add a test to verify setRecords is not called
	// when no updates are necessary.
}

var (
	_ RecordGetterSetter = &testProvider{}
)

type testProvider struct {
	getRecords func(ctx context.Context, zone string) ([]libdns.Record, error)
	setRecords func(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error)
}

func (p *testProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return p.getRecords(ctx, zone)
}

func (p *testProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return p.setRecords(ctx, zone, recs)
}
