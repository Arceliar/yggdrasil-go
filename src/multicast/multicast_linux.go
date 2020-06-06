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
		time.Sleep(time.Second) // FIXME this is bad practice
		if err := netlink.AddrSubscribeWithOptions(addrChanges, addrClose, addrSubscribeOptions); err != nil {
			panic(err)
		}
	}()

	m.log.Debugln("Listening for netlink interface changes")

	go func() {
		defer m.log.Debugln("No longer listening for netlink interface changes")

		indexToIntf := make(map[int]string)
		indexToAddrs := make(map[int]map[string]*net.IPNet)

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

				updateAddrs := func(linkIndex int) {
					name, ok := indexToIntf[linkIndex]
					if !ok {
						return
					}
					info, infoOk := interfaces[name]
					if !infoOk {
						return // Should this ever happen?
					}
					newAddrs := indexToAddrs[linkIndex]
					addrs := make([]net.Addr, 0, len(newAddrs))
					for _, addr := range newAddrs {
						addrs = append(addrs, addr)
					}
					info.addrs = addrs
					interfaces[name] = info
					// The rest is just logging, and should probably be done in the multicast actor instead
					oldAddrs := make(map[string]net.Addr, len(info.addrs))
					for _, addr := range info.addrs {
						oldAddrs[addr.String()] = addr
					}
					// Log any new addresses added
					for addrString, newAddr := range newAddrs {
						if _, isIn := oldAddrs[addrString]; !isIn {
							m.log.Debugln("Multicast address", newAddr.String(), "on", name, "enabled")
						}
					}
					// Log any old addresses removed
					for addrString, oldAddr := range oldAddrs {
						if _, isIn := newAddrs[addrString]; !isIn {
							m.log.Debugln("Multicast address", oldAddr.String(), "on", name, "disabled")
						}
					}
				}

				select {
				case change := <-linkChanges:
					attrs := change.Attrs()
					defer updateAddrs(attrs.Index)
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
					} else if _, isIn := indexToIntf[attrs.Index]; isIn {
						m.log.Debugln("Multicast on interface", attrs.Name, "disabled")
						delete(indexToIntf, attrs.Index)
						//delete(indexToAddrs, attrs.Index) // TODO? Or process messages individually?
						delete(interfaces, attrs.Name)
					}

				case change := <-addrChanges:
					defer updateAddrs(change.LinkIndex)
					add := true
					add = add && change.NewAddr
					add = add && change.LinkAddress.IP.IsLinkLocalUnicast()
					if add {
						if _, isIn := indexToAddrs[change.LinkIndex]; !isIn {
							indexToAddrs[change.LinkIndex] = make(map[string]*net.IPNet)
						}
						changeString := change.LinkAddress.String()
						if _, isIn := indexToAddrs[change.LinkIndex][changeString]; !isIn {
							ipNet := change.LinkAddress
							indexToAddrs[change.LinkIndex][changeString] = &ipNet
							//defer updateAddrs(change.LinkIndex)
						}
					} else {
						if idxAddrs, isIn := indexToAddrs[change.LinkIndex]; isIn {
							changeString := change.LinkAddress.String()
							if _, isIn := idxAddrs[changeString]; isIn {
								delete(idxAddrs, changeString)
								if len(idxAddrs) == 0 {
									delete(indexToAddrs, change.LinkIndex)
								}
								//defer updateAddrs(change.LinkIndex)
							}
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
