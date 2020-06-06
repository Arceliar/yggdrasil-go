// +build !linux

package multicast

import (
	"net"
	"regexp"
)

func (m *Multicast) _updateInterfaces() {
	interfaces := make(map[string]interfaceInfo)
	intfs := m.getAllowedInterfaces()
	for _, intf := range intfs {
		addrs, err := intf.Addrs()
		if err != nil {
			m.log.Warnf("Failed up get addresses for interface %s: %s", intf.Name, err)
			continue
		}
		interfaces[intf.Name] = interfaceInfo{
			iface: intf,
			addrs: addrs,
		}
	}
	m._interfaces = interfaces
}

// getAllowedInterfaces returns the currently known/enabled multicast interfaces.
func (m *Multicast) getAllowedInterfaces() map[string]net.Interface {
	interfaces := make(map[string]net.Interface)
	// Get interface expressions from config
	current := m.config.GetCurrent()
	exprs := current.MulticastInterfaces
	// Ask the system for network interfaces
	allifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	// Work out which interfaces to announce on
	for _, iface := range allifaces {
		if iface.Flags&net.FlagUp == 0 {
			// Ignore interfaces that are down
			continue
		}
		if iface.Flags&net.FlagMulticast == 0 {
			// Ignore non-multicast interfaces
			continue
		}
		if iface.Flags&net.FlagPointToPoint != 0 {
			// Ignore point-to-point interfaces
			continue
		}
		for _, expr := range exprs {
			// Compile each regular expression
			e, err := regexp.Compile(expr)
			if err != nil {
				panic(err)
			}
			// Does the interface match the regular expression? Store it if so
			if e.MatchString(iface.Name) {
				interfaces[iface.Name] = iface
			}
		}
	}
	return interfaces
}
