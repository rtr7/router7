// Package backup generates tarballs of /perm.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

func Archive(w io.Writer, dir string) error {
	gw, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
	if err != nil {
		return err
	}
	defer gw.Close()
	tw := tar.NewWriter(gw)

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info == nil {
			return fmt.Errorf("filepath.Walk: nil os.FileInfo")
		}
		if !info.Mode().IsRegular() && !info.Mode().IsDir() {
			return nil // skip non-regular files/directories
		}
		if path == dir {
			return nil // skip root
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsDir() {
			b, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			if _, err := tw.Write(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	if err := tw.Close(); err != nil {
		return err
	}
	return gw.Close()
}
