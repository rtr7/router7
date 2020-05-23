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

	"github.com/libdns/libdns"
)

type RecordGetterSetter interface {
	libdns.RecordGetter
	libdns.RecordSetter
}

// Update takes a record which should be updated
// within the specified zone.
func Update(ctx context.Context, zone string, record libdns.Record, provider RecordGetterSetter) error {
	existing, err := provider.GetRecords(ctx, zone)
	if err != nil {
		return err
	}

	var updated []libdns.Record
	for _, rec := range existing {
		if rec.Name != record.Name || rec.Type != record.Type {
			continue
		}

		if rec.Value == record.Value {
			log.Printf("exit early: record up to date (%s)", record.Value)
			return nil
		}

		// TODO: it appears the cloudflare provider expects a non-empty ID to
		// mean that a record should be created rather than updated. This behavior
		// means that we clear the ID to force an update by the zone name.
		//
		// See: https://github.com/libdns/cloudflare/issues/1.
		rec.ID = ""
		rec.Value = record.Value
		updated = append(updated, rec)
		break
	}
	if len(updated) == 0 {
		updated = []libdns.Record{record}
	}

	if _, err := provider.SetRecords(ctx, zone, updated); err != nil {
		return err
	}
	return nil
}
