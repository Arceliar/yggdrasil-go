// +build linux

package multicast

import (
	"net"
	"regexp"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func (m *Multicast) _multicastStarted() {
	linkChanges := make(chan netlink.LinkUpdate)
	addrChanges := make(chan netlink.AddrUpdate)

	linkClose := make(chan struct{})
	addrClose := make(chan struct{})

	errorCallback := func(err error) {
		m.log.Warnln("Netlink error:", err)
	}

	linkSubscribeOptions := netlink.LinkSubscribeOptions{
		ListExisting:  true,
		ErrorCallback: errorCallback,
	}

	addrSubscribeOptions := netlink.AddrSubscribeOptions{
		ListExisting:  true,
		ErrorCallback: errorCallback,
	}

	if err := netlink.LinkSubscribeWithOptions(linkChanges, linkClose, linkSubscribeOptions); err != nil {
		panic(err)
	}

	go func() {
		time.Sleep(time.Second)
		if err := netlink.AddrSubscribeWithOptions(addrChanges, addrClose, addrSubscribeOptions); err != nil {
			panic(err)
		}
	}()

	m.log.Debugln("Listening for netlink interface changes")

	go func() {
		defer m.log.Debugln("No longer listening for netlink interface changes")

		indexToIntf := map[int]string{}

		for {
			current := m.config.GetCurrent()
			exprs := current.MulticastInterfaces

			select {
			case change := <-linkChanges:
				attrs := change.Attrs()
				add := true
				add = add && attrs.Flags&net.FlagUp != 0
				add = add && attrs.Flags&net.FlagMulticast != 0
				add = add && attrs.Flags&net.FlagPointToPoint == 0

				if add {
					match := false
					for _, expr := range exprs {
						e, err := regexp.Compile(expr)
						if err != nil {
							panic(err)
						}
						if e.MatchString(attrs.Name) {
							match = true
							break
						}
					}
					add = add && match
				}

				if add {
					indexToIntf[attrs.Index] = attrs.Name
					m.Act(nil, func() {
						iface, err := net.InterfaceByIndex(attrs.Index)
						if err != nil {
							return
						}
						m.log.Debugln("Multicast on interface", attrs.Name, "enabled")
						if info, ok := m._interfaces[attrs.Name]; ok {
							info.iface = *iface
							m._interfaces[attrs.Name] = info
						} else {
							m._interfaces[attrs.Name] = interfaceInfo{
								iface: *iface,
							}
						}
					})
				} else {
					delete(indexToIntf, attrs.Index)
					m.Act(nil, func() {
						m.log.Debugln("Multicast on interface", attrs.Name, "disabled")
						delete(m._interfaces, attrs.Name)
					})
				}

			case change := <-addrChanges:
				name, ok := indexToIntf[change.LinkIndex]
				if !ok {
					break
				}
				add := true
				add = add && change.NewAddr
				add = add && change.LinkAddress.IP.IsLinkLocalUnicast()

				if add {
					m.Act(nil, func() {
						m.log.Debugln("Multicast address", change.LinkAddress.IP, "on", name, "enabled")
						if info, ok := m._interfaces[name]; ok {
							// We need to ParseCIDR the Addr, so use an IPNet
							info.addrs = append(info.addrs, &net.IPNet{
								IP:   change.LinkAddress.IP,
								Mask: net.CIDRMask(64, 128),
							})
							m._interfaces[name] = info
						}
					})
				} else {
					m.Act(nil, func() {
						m.log.Debugln("Multicast address", change.LinkAddress.IP, "on", name, "disabled")
						if info, ok := m._interfaces[name]; ok {
							info.addrs = nil
							m._interfaces[name] = info
						}
					})
				}

			case <-linkClose:
				return

			case <-addrClose:
				return

			case <-m.stop:
				close(linkClose)
				close(addrClose)
				return
			}
		}
	}()
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
