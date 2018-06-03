package diag

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

type link struct {
	children []Node
	ifname   string
}

func (l *link) String() string {
	return "link/" + l.ifname
}

func (l *link) Then(t Node) Node {
	l.children = append(l.children, t)
	return l
}

func (l *link) Children() []Node {
	return l.children
}

func (l *link) Evaluate() (string, error) {
	link, err := netlink.LinkByName(l.ifname)
	if err != nil {
		return "", err
	}
	attrs := link.Attrs()

	// TODO: check RUNNING as well?
	if attrs.Flags&net.FlagUp == 0 {
		return "", fmt.Errorf("link %s not UP", l.ifname)
	}

	return fmt.Sprintf("%d rx, %d tx", attrs.Statistics.RxPackets, attrs.Statistics.TxPackets), nil
}

// Link returns a Node which succeeds when the specified network interface is in
// state UP and RUNNING.
func Link(ifname string) Node {
	return &link{ifname: ifname}
}
