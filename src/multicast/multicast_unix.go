// +build netbsd freebsd openbsd dragonflybsd

package multicast

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func (m *Multicast) _multicastStarted() {

}

func (m *Multicast) multicastReuse(network string, address string, c syscall.RawConn) error {
	var control error
	var reuseport error

	control = c.Control(func(fd uintptr) {
		reuseport = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})

	switch {
	case reuseport != nil:
		return reuseport
	default:
		return control
	}
}
