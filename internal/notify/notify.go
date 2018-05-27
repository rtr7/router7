package notify

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var numericRe = regexp.MustCompile(`^[0-9]+$`)

func Process(name string, sig os.Signal) error {
	fis, err := ioutil.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, fi := range fis {
		if !fi.IsDir() {
			continue
		}
		if !numericRe.MatchString(fi.Name()) {
			continue
		}
		b, err := ioutil.ReadFile(filepath.Join("/proc", fi.Name(), "cmdline"))
		if err != nil {
			return err
		}
		if !strings.HasPrefix(string(b), name) {
			continue
		}
		pid, _ := strconv.Atoi(fi.Name()) // already verified to be numeric
		p, _ := os.FindProcess(pid)
		return p.Signal(sig)
	}
	return nil
}
