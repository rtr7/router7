package oui

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestDB(t *testing.T) {
	t.Parallel()

	const (
		ubiquitiBlock = "f0:9f:c2"
		salcompBlock  = "44:09:b8"
	)

	tmpdir, err := ioutil.TempDir("", "oui")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	t.Run("FromScratch", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Last-Modified", "Sun, 06 Jan 2019 15:03:46 GMT")
			io.WriteString(w, `Registry,Assignment,Organization Name,Organization Address
MA-L,F09FC2,Ubiquiti Networks Inc.,2580 Orchard Parkway San Jose CA US 95131
MA-L,4409B8,"Salcomp (Shenzhen) CO., LTD.","Salcomp Road, Furong Industrial Area, Xinqiao, Shajing, Baoan District Shenzhen Guangdong CN 518125 "
`)
		}))
		defer srv.Close()

		db := NewDB(tmpdir)
		db.ouiURL = srv.URL
		if err := db.WaitUntilLoaded(); err != nil {
			t.Fatal(err)
		}

		if got, want := db.Lookup(ubiquitiBlock), "Ubiquiti Networks Inc."; got != want {
			t.Errorf("db.Lookup(%q) = %v, want %v", ubiquitiBlock, got, want)
		}

		if got, want := db.Lookup(salcompBlock), "Salcomp (Shenzhen) CO., LTD."; got != want {
			t.Errorf("db.Lookup(%q) = %v, want %v", salcompBlock, got, want)
		}
	})

	t.Run("BrokenUpstream", func(t *testing.T) {
		unblock := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-unblock
			http.Error(w, "yuck!", http.StatusInternalServerError)
		}))
		defer srv.Close()

		db := NewDB(tmpdir)
		db.ouiURL = srv.URL
		if err := db.WaitUntilLoaded(); err != nil {
			t.Fatal(err)
		}

		if got, want := db.Lookup(ubiquitiBlock), "Ubiquiti Networks Inc."; got != want {
			t.Errorf("db.Lookup(%q) = %v, want %v", ubiquitiBlock, got, want)
		}

		db.Lock()
		db.loaded = false // reset so that we can wait again
		db.Unlock()
		unblock <- struct{}{}
		if err := db.WaitUntilLoaded(); err == nil {
			t.Fatal("db.WaitUntilLoaded returned no error despite HTTP 500")
		}

		if got, want := db.Lookup(ubiquitiBlock), "Ubiquiti Networks Inc."; got != want {
			t.Errorf("db.Lookup(%q) = %v, want %v", ubiquitiBlock, got, want)
		}
	})

	t.Run("NoUpdates", func(t *testing.T) {
		unblock := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-unblock
			w.WriteHeader(http.StatusNotModified)
		}))
		defer srv.Close()

		db := NewDB(tmpdir)
		db.ouiURL = srv.URL
		if err := db.WaitUntilLoaded(); err != nil {
			t.Fatal(err)
		}

		if got, want := db.Lookup(ubiquitiBlock), "Ubiquiti Networks Inc."; got != want {
			t.Errorf("db.Lookup(%q) = %v, want %v", ubiquitiBlock, got, want)
		}

		db.Lock()
		db.loaded = false // reset so that we can wait again
		db.Unlock()
		unblock <- struct{}{}
		if err := db.WaitUntilLoaded(); err != nil {
			t.Fatal(err)
		}

		if got, want := db.Lookup(ubiquitiBlock), "Ubiquiti Networks Inc."; got != want {
			t.Errorf("db.Lookup(%q) = %v, want %v", ubiquitiBlock, got, want)
		}
	})

	t.Run("Update", func(t *testing.T) {
		unblock := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-unblock
			w.Header().Set("Last-Modified", "Sun, 06 Jan 2019 15:03:49 GMT")
			io.WriteString(w, `Registry,Assignment,Organization Name,Organization Address
MA-L,F09FC2,Obiquiti Networks Inc.,2580 Orchard Parkway San Jose CA US 95131
`)
		}))
		defer srv.Close()

		db := NewDB(tmpdir)
		db.ouiURL = srv.URL
		if err := db.WaitUntilLoaded(); err != nil {
			t.Fatal(err)
		}

		if got, want := db.Lookup(ubiquitiBlock), "Ubiquiti Networks Inc."; got != want {
			t.Errorf("db.Lookup(%q) = %v, want %v", ubiquitiBlock, got, want)
		}

		db.Lock()
		db.loaded = false // reset so that we can wait again
		db.Unlock()
		unblock <- struct{}{}
		if err := db.WaitUntilLoaded(); err != nil {
			t.Fatal(err)
		}

		if got, want := db.Lookup(ubiquitiBlock), "Obiquiti Networks Inc."; got != want {
			t.Errorf("db.Lookup(%q) = %v, want %v", ubiquitiBlock, got, want)
		}
	})
}
