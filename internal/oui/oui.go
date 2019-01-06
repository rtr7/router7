package oui

import (
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/renameio"
)

// DB is a IEEE MA-L (MAC Address Block Large, formerly known as OUI) database.
type DB struct {
	dir    string // where to store our cache of oui.csv
	ouiURL string // can be overridden for testing

	sync.Mutex
	cond   *sync.Cond
	loaded bool
	err    error

	// orgs is a map from assignment (e.g. f0:9f:c2) to organization name
	// (e.g. Ubiquiti Networks Inc.), gathered from the IEEE MA-L (MAC Address
	// Block Large, formerly known as OUI):
	// https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries
	orgs map[string]string
}

type option func(d *DB)

func ouiURL(u string) option {
	return func(d *DB) {
		d.ouiURL = u
	}
}

// NewDB loads a database from the cached version in dir, if any, and
// asynchronously triggers an update. Use WaitUntilLoaded() to ensure Lookup()
// will work, or use Lookup() opportunistically at any time.
func NewDB(dir string, opts ...option) *DB {
	db := &DB{
		dir:    dir,
		ouiURL: "http://standards-oui.ieee.org/oui/oui.csv",
	}
	db.cond = sync.NewCond(&db.Mutex)
	for _, o := range opts {
		o(db)
	}
	go db.update()
	return db
}

// Lookup returns the organization name for the specified assignment, if
// found. Assignment is a large MAC address block assignment, e.g. f0:9f:c2.
func (d *DB) Lookup(assignment string) string {
	d.Lock()
	defer d.Unlock()
	return d.orgs[assignment]
}

// WaitUntilLoaded blocks until the database was loaded.
func (d *DB) WaitUntilLoaded() error {
	d.Lock()
	defer d.Unlock()
	for !d.loaded {
		d.cond.Wait()
	}
	return d.err
}

func (d *DB) setErr(err error) {
	d.Lock()
	defer d.Unlock()
	d.loaded = true
	d.cond.Broadcast()
	d.err = err
}

func (d *DB) update() {
	req, err := http.NewRequest("GET", d.ouiURL, nil)
	if err != nil {
		d.setErr(err)
		return
	}

	csvPath := filepath.Join(d.dir, "oui.csv")
	// If any version exists, load it so that lookups work ASAP:
	if f, err := os.Open(csvPath); err == nil {
		if st, err := f.Stat(); err == nil {
			req.Header.Set("If-Modified-Since", st.ModTime().UTC().Format(http.TimeFormat))
		}
		defer f.Close()
		if err := d.load(f); err != nil {
			// Force a re-download in case our file is corrupted:
			req.Header.Del("If-Modified-Since")
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		d.setErr(err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		d.setErr(nil)
		return // already up-to-date
	}
	if got, want := resp.StatusCode, http.StatusOK; got != want {
		body, _ := ioutil.ReadAll(resp.Body)
		d.setErr(fmt.Errorf("%s: unexpected HTTP status: got %v, want %v (%v)", d.ouiURL, resp.Status, want, body))
		return
	}
	if err := os.MkdirAll(d.dir, 0755); err != nil {
		d.setErr(err)
		return
	}
	f, err := renameio.TempFile(d.dir, csvPath)
	if err != nil {
		d.setErr(err)
		return
	}
	defer f.Cleanup()
	if _, err := io.Copy(f, resp.Body); err != nil {
		d.setErr(err)
		return
	}
	if t, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		if err := os.Chtimes(f.Name(), t, t); err != nil {
			log.Print(err)
		}
	}
	if err := f.CloseAtomicallyReplace(); err != nil {
		d.setErr(err)
		return
	}
	{
		f, err := os.Open(csvPath)
		if err != nil {
			d.setErr(err)
			return
		}
		defer f.Close()
		d.setErr(d.load(f))
	}
}

func (d *DB) load(r io.Reader) error {
	// As of 2019-01, we’re talking < 30000 records.
	records, err := csv.NewReader(r).ReadAll()
	if err != nil {
		return err
	}
	orgs := make(map[string]string, len(records))
	var buf [3]byte
	for _, record := range records[1:] {
		assignment, org := record[1], record[2]
		n, err := hex.Decode(buf[:], []byte(assignment))
		if err != nil {
			return fmt.Errorf("hex.Decode(%s): %v", assignment, err)
		}
		if got, want := n, 3; got != want {
			return fmt.Errorf("decode assignment %q: got %d bytes, want %d bytes", assignment, got, want)
		}
		orgs[fmt.Sprintf("%02x:%02x:%02x", buf[0], buf[1], buf[2])] = org
	}
	d.Lock()
	defer d.Unlock()
	d.orgs = orgs
	d.loaded = true
	d.cond.Broadcast()
	return nil
}
