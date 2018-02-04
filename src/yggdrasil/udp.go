package yggdrasil

// This communicates with peers via UDP
// It's not as well tested or debugged as the TCP transport
// It's intended to use UDP, so debugging/optimzing this is a high priority
// TODO? use golang.org/x/net/ipv6.PacketConn's ReadBatch and WriteBatch?
//  To send all chunks of a message / recv all available chunks in one syscall
//  That might be faster on supported platforms, but it needs investigation
// Chunks are currently murged, but outgoing messages aren't chunked
// This is just to support chunking in the future, if it's needed and debugged
//  Basically, right now we might send UDP packets that are too large

// TODO remove old/unused code and better document live code

import "net"
import "time"
import "sync"
import "fmt"

import "golang.org/x/net/ipv6"

type udpInterface struct {
	core  *Core
	sock  *net.UDPConn // Or more general PacketConn?
	mutex sync.RWMutex // each conn has an owner goroutine
	conns map[connAddr]*connInfo
}

type connAddr struct {
	ip   [16]byte
	port int
	zone string
}

func (c *connAddr) fromUDPAddr(u *net.UDPAddr) {
	copy(c.ip[:], u.IP.To16())
	c.port = u.Port
	c.zone = u.Zone
}

func (c *connAddr) toUDPAddr() *net.UDPAddr {
	var u net.UDPAddr
	u.IP = make([]byte, 16)
	copy(u.IP, c.ip[:])
	u.Port = c.port
	u.Zone = c.zone
	return &u
}

type connInfo struct {
	name     string
	addr     connAddr
	peer     *peer
	linkIn   chan []byte
	keysIn   chan *udpKeys
	timeout  int // count of how many heartbeats have been missed
	in       func([]byte)
	out      chan []byte
	countIn  uint8
	countOut uint8
}

type udpKeys struct {
	box boxPubKey
	sig sigPubKey
}

func (iface *udpInterface) init(core *Core, addr string) {
	iface.core = core
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		panic(err)
	}
	iface.sock, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		panic(err)
	}
	iface.conns = make(map[connAddr]*connInfo)
	go iface.reader()
}

func (iface *udpInterface) sendKeys(addr connAddr) {
	udpAddr := addr.toUDPAddr()
	msg := []byte{}
	msg = udp_encode(msg, 0, 0, 0, nil)
	msg = append(msg, iface.core.boxPub[:]...)
	msg = append(msg, iface.core.sigPub[:]...)
	iface.sock.WriteToUDP(msg, udpAddr)
}

func udp_isKeys(msg []byte) bool {
	keyLen := 3 + boxPubKeyLen + sigPubKeyLen
	return len(msg) == keyLen && msg[0] == 0x00
}

func (iface *udpInterface) startConn(info *connInfo) {
	ticker := time.NewTicker(6 * time.Second)
	defer ticker.Stop()
	defer func() {
		// Cleanup
		// FIXME this still leaks a peer struct
		iface.mutex.Lock()
		delete(iface.conns, info.addr)
		iface.mutex.Unlock()
		iface.core.peers.mutex.Lock()
		oldPorts := iface.core.peers.getPorts()
		newPorts := make(map[switchPort]*peer)
		for k, v := range oldPorts {
			newPorts[k] = v
		}
		delete(newPorts, info.peer.port)
		iface.core.peers.putPorts(newPorts)
		iface.core.peers.mutex.Unlock()
		close(info.linkIn)
		close(info.keysIn)
		close(info.out)
		iface.core.log.Println("Removing peer:", info.name)
	}()
	for {
		select {
		case ks := <-info.keysIn:
			{
				// FIXME? need signatures/sequence-numbers or something
				// Spoofers could lock out a peer with fake/bad keys
				if ks.box == info.peer.box && ks.sig == info.peer.sig {
					info.timeout = 0
				}
			}
		case <-ticker.C:
			{
				if info.timeout > 10 {
					return
				}
				info.timeout++
				iface.sendKeys(info.addr)
			}
		}
	}
}

func (iface *udpInterface) handleKeys(msg []byte, addr connAddr) {
	//defer util_putBytes(msg)
	var ks udpKeys
	_, _, _, bs := udp_decode(msg)
	switch {
	case !wire_chop_slice(ks.box[:], &bs):
		return
	case !wire_chop_slice(ks.sig[:], &bs):
		return
	}
	if ks.box == iface.core.boxPub {
		return
	}
	if ks.sig == iface.core.sigPub {
		return
	}
	iface.mutex.RLock()
	conn, isIn := iface.conns[addr]
	iface.mutex.RUnlock()
	if !isIn {
		udpAddr := addr.toUDPAddr()
		themNodeID := getNodeID(&ks.box)
		themAddr := address_addrForNodeID(themNodeID)
		themAddrString := net.IP(themAddr[:]).String()
		themString := fmt.Sprintf("%s@%s", themAddrString, udpAddr.String())
		conn = &connInfo{
			name:   themString,
			addr:   connAddr(addr),
			peer:   iface.core.peers.newPeer(&ks.box, &ks.sig),
			linkIn: make(chan []byte, 1),
			keysIn: make(chan *udpKeys, 1),
			out:    make(chan []byte, 32),
		}
		var inChunks uint8
		var inBuf []byte
		conn.in = func(bs []byte) {
			//defer util_putBytes(bs)
			chunks, chunk, count, payload := udp_decode(bs)
			//iface.core.log.Println("DEBUG:", addr, chunks, chunk, count, len(payload))
			//iface.core.log.Println("DEBUG: payload:", payload)
			if count != conn.countIn {
				inChunks = 0
				inBuf = inBuf[:0]
				conn.countIn = count
			}
			if chunk <= chunks && chunk == inChunks+1 {
				//iface.core.log.Println("GOING:", addr, chunks, chunk, count, len(payload))
				inChunks += 1
				inBuf = append(inBuf, payload...)
				if chunks != chunk {
					return
				}
				msg := append(util_getBytes(), inBuf...)
				conn.peer.handlePacket(msg, conn.linkIn)
				//iface.core.log.Println("DONE:", addr, chunks, chunk, count, len(payload))
			}
		}
		conn.peer.out = func(msg []byte) {
			defer func() { recover() }()
			for {
				select {
				case conn.out <- msg:
					return
				default:
					util_putBytes(<-conn.out)
				}
			}
		}
		go func() {
			var msgs []ipv6.Message
			var chunks [][]byte
			pconn := ipv6.NewPacketConn(iface.sock)
			for msg := range conn.out {
				chunks = chunks[:0]
				bs := msg
				for len(bs) > udp_chunkSize {
					chunks, bs = append(chunks, bs[:udp_chunkSize]), bs[udp_chunkSize:]
				}
				chunks = append(chunks, bs)
				//iface.core.log.Println("DEBUG: out chunks:", len(chunks), len(msg))
				if len(chunks) > 255 {
					continue
				}
				msgs = msgs[:0]
				size := 0
				for idx, bs := range chunks {
					nChunks, nChunk, count := uint8(len(chunks)), uint8(idx)+1, conn.countOut
					m := ipv6.Message{
						Buffers: [][]byte{{nChunks, nChunk, count}, bs},
						Addr:    udpAddr,
					}
					msgs = append(msgs, m)
					size += 3 + len(bs)
				}
				start := time.Now()
				for idx := 0; idx < len(msgs); {
					written, _ := pconn.WriteBatch(msgs[idx:], 0)
					idx += written
				}
				timed := time.Since(start)
				conn.countOut += 1
				conn.peer.updateBandwidth(size, timed)
				util_putBytes(msg)
			}
		}()
		//*/
		iface.mutex.Lock()
		iface.conns[addr] = conn
		iface.mutex.Unlock()
		iface.core.log.Println("Adding peer:", conn.name)
		go iface.startConn(conn)
		go conn.peer.linkLoop(conn.linkIn)
		iface.sendKeys(conn.addr)
	}
	func() {
		defer func() { recover() }()
		select {
		case conn.keysIn <- &ks:
		default:
		}
	}()
}

func (iface *udpInterface) handlePacket(msg []byte, addr connAddr) {
	iface.mutex.RLock()
	if conn, isIn := iface.conns[addr]; isIn {
		conn.in(msg)
	}
	iface.mutex.RUnlock()
}

func (iface *udpInterface) reader() {
	bs := make([]byte, 2048) // This needs to be large enough for everything...
	for {
		//iface.core.log.Println("Starting read")
		n, udpAddr, err := iface.sock.ReadFromUDP(bs)
		//iface.core.log.Println("Read", n, udpAddr.String(), err)
		if err != nil {
			panic(err)
			break
		}
		if n > 1500 {
			panic(n)
		}
		//msg := append(util_getBytes(), bs[:n]...)
		msg := bs[:n]
		var addr connAddr
		addr.fromUDPAddr(udpAddr)
		if udp_isKeys(msg) {
			var them address
			copy(them[:], udpAddr.IP.To16())
			if them.isValid() {
				continue
			}
			if udpAddr.IP.IsLinkLocalUnicast() &&
				!iface.core.ifceExpr.MatchString(udpAddr.Zone) {
				continue
			}
			iface.handleKeys(msg, addr)
		} else {
			iface.handlePacket(msg, addr)
		}
	}
}

////////////////////////////////////////////////////////////////////////////////

const udp_chunkSize = 1024

func udp_decode(bs []byte) (chunks, chunk, count uint8, payload []byte) {
	if len(bs) >= 3 {
		chunks, chunk, count, payload = bs[0], bs[1], bs[2], bs[3:]
	}
	return
}

func udp_encode(out []byte, chunks, chunk, count uint8, payload []byte) []byte {
	return append(append(out, chunks, chunk, count), payload...)
}
