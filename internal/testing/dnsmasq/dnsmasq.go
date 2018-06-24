// Package dnsmasq manages the process lifecycle of the dnsmasq(8) DHCP server.
package dnsmasq

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Process is a handle for a dnsmasq(8) process.
type Process struct {
	killed  bool          // whether Kill was called
	done    chan struct{} // closed when Done() is called
	wait    chan struct{} // closed when Wait() returns
	dnsmasq *exec.Cmd

	mu      sync.Mutex
	actions []string
}

var dhcpActionRe = regexp.MustCompile(` (DHCP[^(]+\(.*)$`)

// Run starts a dnsmasq(8) process and returns a handle to it.
func Run(t *testing.T, iface, ns string) *Process {
	ready, err := ioutil.TempFile("", "router7")
	if err != nil {
		t.Fatal(err)
	}
	ready.Close()                 // dnsmasq will re-create the file anyway
	defer os.Remove(ready.Name()) // dnsmasq does not clean up its pid file

	// iface, err := net.InterfaceByName("veth0a")
	// if err != nil {
	// 	t.Fatal(err)
	// }

	p := &Process{
		wait: make(chan struct{}),
	}

	p.dnsmasq = exec.Command("ip", "netns", "exec", ns, "dnsmasq",
		"--keep-in-foreground", // cannot use --no-daemon because we need --pid-file
		"--log-facility=-",     // log to stderr
		"--pid-file="+ready.Name(),
		"--bind-interfaces",
		"--interface="+iface,
		"--dhcp-range=192.168.23.2,192.168.23.10",
		"--dhcp-range=::1,::10,constructor:"+iface,
		"--dhcp-authoritative", // eliminate timeouts
		"--no-ping",            // disable ICMP confirmation of unused addresses to eliminate tedious timeout
		"--leasefile-ro",       // do not create a lease database
	)

	p.dnsmasq.Stdout = os.Stdout
	stderr := make(chan string)
	r, w := io.Pipe()
	scanner := bufio.NewScanner(r)
	go func() {
		for scanner.Scan() {
			stderr <- scanner.Text()
		}
		close(stderr)
	}()
	p.dnsmasq.Stderr = w
	//mac := iface.HardwareAddr.String()
	go func() {
		for line := range stderr {
			fmt.Printf("dnsmasq log line: %s\n", line)
			if !strings.HasPrefix(line, "dnsmasq-dhcp") {
				continue
			}
			// if !strings.Contains(line, mac) {
			// 	continue
			// }
			matches := dhcpActionRe.FindStringSubmatch(line)
			if matches == nil {
				continue
			}
			p.mu.Lock()
			p.actions = append(p.actions, matches[1])
			p.mu.Unlock()
		}
	}()
	if err := p.dnsmasq.Start(); err != nil {
		t.Fatal(err)
	}

	p.done = make(chan struct{})
	go func() {
		err := p.dnsmasq.Wait()
		close(p.wait)
		select {
		case <-p.done:
			return // test done, any errors are from our Kill()
		default:
			t.Fatalf("dnsmasq exited prematurely: %v", err)
		}
	}()

	// TODO(later): use inotify instead of polling
	// Wait for dnsmasq to write its process id, at which point it is already
	// listening for requests.
	for {
		b, err := ioutil.ReadFile(ready.Name())
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(b)) == strconv.Itoa(p.dnsmasq.Process.Pid) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return p
}

// Kill shuts down the dnsmasq(8) process and returns once waitpid returns.
func (p *Process) Kill() {
	if p.killed {
		return
	}
	p.killed = true
	close(p.done)
	p.dnsmasq.Process.Kill()
	<-p.wait
}

// Actions returns a string slice of dnsmasq(8) actions (as per its stderr log)
// received up until now. Use Kill before calling Actions to force a log flush.
func (p *Process) Actions() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make([]string, len(p.actions))
	copy(result, p.actions)
	return result
}
