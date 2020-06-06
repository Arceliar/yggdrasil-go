// +build linux

package multicast

import (
	"net"
	"regexp"
	"syscall"
	"time"

	"github.com/Arceliar/phony"
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
			f := func() map[string]interfaceInfo {
				var oldInterfaces map[string]interfaceInfo
				phony.Block(m, func() {
					oldInterfaces = m._interfaces
				})
				interfaces := make(map[string]interfaceInfo, len(oldInterfaces)+1)
				for k, v := range oldInterfaces {
					interfaces[k] = v
				}
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
						func() {
							iface, err := net.InterfaceByIndex(attrs.Index)
							if err != nil {
								return
							}
							m.log.Debugln("Multicast on interface", attrs.Name, "enabled")
							if info, ok := interfaces[attrs.Name]; ok {
								info.iface = *iface
								interfaces[attrs.Name] = info
							} else {
								interfaces[attrs.Name] = interfaceInfo{
									iface: *iface,
								}
							}
						}()
					} else {
						delete(indexToIntf, attrs.Index)
						m.log.Debugln("Multicast on interface", attrs.Name, "disabled")
						delete(interfaces, attrs.Name)
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
						m.log.Debugln("Multicast address", change.LinkAddress.IP, "on", name, "enabled")
						if info, ok := interfaces[name]; ok {
							// We need to ParseCIDR the Addr, so use an IPNet
							info.addrs = append([]net.Addr(nil), info.addrs...) // copy
							info.addrs = append(info.addrs, &net.IPNet{
								IP:   change.LinkAddress.IP,
								Mask: net.CIDRMask(64, 128),
							})
							interfaces[name] = info
						}
					} else {
						m.log.Debugln("Multicast address", change.LinkAddress.IP, "on", name, "disabled")
						if info, ok := interfaces[name]; ok {
							oldAddrs := info.addrs
							info.addrs = nil
							changedAddr := net.IPNet{
								IP:   change.LinkAddress.IP,
								Mask: net.CIDRMask(64, 128),
							}
							changedString := changedAddr.String()
							for _, addr := range oldAddrs {
								if addr.String() == changedString {
									continue
								}
								info.addrs = append(info.addrs, addr)
							}
							interfaces[name] = info
						}
					}

				case <-linkClose:
					return nil

				case <-addrClose:
					return nil

				case <-m.stop:
					close(linkClose)
					close(addrClose)
					return nil
				}
				return interfaces
			}
			if interfaces := f(); interfaces != nil {
				// Update m._interfaces
				m.Act(nil, func() {
					m._interfaces = interfaces
				})
			} else {
				// Exit
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
