package yggdrasil

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"

	//"sync/atomic"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/crypto"
	"github.com/yggdrasil-network/yggdrasil-go/src/util"
	"golang.org/x/net/proxy"

	"github.com/Arceliar/phony"
)

type links struct {
	core    *Core
	mutex   sync.RWMutex // protects links below
	links   map[linkInfo]*link
	tcp     tcp // TCP interface support
	stopped chan struct{}
	// TODO timeout (to remove from switch), read from config.ReadTimeout
}

type linkInfo struct {
	box      crypto.BoxPubKey // Their encryption key
	sig      crypto.SigPubKey // Their signing key
	linkType string           // Type of link, e.g. TCP, AWDL
	local    string           // Local name or address
	remote   string           // Remote name or address
}

type linkMsgIO interface {
	readMsg() ([]byte, error)
	writeMsgs([][]byte) (int, error)
	close() error
	// These are temporary workarounds to stream semantics
	_sendMetaBytes([]byte) error
	_recvMetaBytes() ([]byte, error)
}

type link struct {
	lname          string
	links          *links
	peer           *peer
	options        linkOptions
	msgIO          linkMsgIO
	info           linkInfo
	incoming       bool
	force          bool
	closed         chan struct{}
	reader         linkReader  // Reads packets, notifies this link, passes packets to switch
	writer         linkWriter  // Writes packets, notifies this link
	phony.Inbox                // Protects the below
	sendTimer      *time.Timer // Fires to signal that sending is blocked
	keepAliveTimer *time.Timer // Fires to send keep-alive traffic
	stallTimer     *time.Timer // Fires to signal that no incoming traffic (including keep-alive) has been seen
	closeTimer     *time.Timer // Fires when the link has been idle so long we need to close it
	readUnblocked  bool        // True if we've sent a read message unblocking this peer in the switch
	writeUnblocked bool        // True if we've sent a write message unblocking this peer in the swithc
	shutdown       bool        // True if we're shutting down, avoids sending some messages that could race with new peers being crated in the same port
}

type linkOptions struct {
	pinnedCurve25519Keys map[crypto.BoxPubKey]struct{}
	pinnedEd25519Keys    map[crypto.SigPubKey]struct{}
}

func (l *links) init(c *Core) error {
	l.core = c
	l.mutex.Lock()
	l.links = make(map[linkInfo]*link)
	l.mutex.Unlock()
	l.stopped = make(chan struct{})

	if err := l.tcp.init(l); err != nil {
		c.log.Errorln("Failed to start TCP interface")
		return err
	}

	return nil
}

func (l *links) reconfigure() {
	l.tcp.reconfigure()
}

func (l *links) call(uri string, sintf string) error {
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("peer %s is not correctly formatted (%s)", uri, err)
	}
	pathtokens := strings.Split(strings.Trim(u.Path, "/"), "/")
	tcpOpts := tcpOptions{}
	if pubkeys, ok := u.Query()["curve25519"]; ok && len(pubkeys) > 0 {
		tcpOpts.pinnedCurve25519Keys = make(map[crypto.BoxPubKey]struct{})
		for _, pubkey := range pubkeys {
			if boxPub, err := hex.DecodeString(pubkey); err == nil {
				var boxPubKey crypto.BoxPubKey
				copy(boxPubKey[:], boxPub)
				tcpOpts.pinnedCurve25519Keys[boxPubKey] = struct{}{}
			}
		}
	}
	if pubkeys, ok := u.Query()["ed25519"]; ok && len(pubkeys) > 0 {
		tcpOpts.pinnedEd25519Keys = make(map[crypto.SigPubKey]struct{})
		for _, pubkey := range pubkeys {
			if sigPub, err := hex.DecodeString(pubkey); err == nil {
				var sigPubKey crypto.SigPubKey
				copy(sigPubKey[:], sigPub)
				tcpOpts.pinnedEd25519Keys[sigPubKey] = struct{}{}
			}
		}
	}
	switch u.Scheme {
	case "tcp":
		l.tcp.call(u.Host, tcpOpts, sintf)
	case "socks":
		tcpOpts.socksProxyAddr = u.Host
		if u.User != nil {
			tcpOpts.socksProxyAuth = &proxy.Auth{}
			tcpOpts.socksProxyAuth.User = u.User.Username()
			tcpOpts.socksProxyAuth.Password, _ = u.User.Password()
		}
		l.tcp.call(pathtokens[0], tcpOpts, sintf)
	case "tls":
		tcpOpts.upgrade = l.tcp.tls.forDialer
		l.tcp.call(u.Host, tcpOpts, sintf)
	default:
		return errors.New("unknown call scheme: " + u.Scheme)
	}
	return nil
}

func (l *links) listen(uri string) error {
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("listener %s is not correctly formatted (%s)", uri, err)
	}
	switch u.Scheme {
	case "tcp":
		_, err := l.tcp.listen(u.Host, nil)
		return err
	case "tls":
		_, err := l.tcp.listen(u.Host, l.tcp.tls.forListener)
		return err
	default:
		return errors.New("unknown listen scheme: " + u.Scheme)
	}
}

func (l *links) create(msgIO linkMsgIO, name, linkType, local, remote string, incoming, force bool, options linkOptions) (*link, error) {
	// Technically anything unique would work for names, but let's pick something human readable, just for debugging
	intf := link{
		lname:   name,
		links:   l,
		options: options,
		msgIO:   msgIO,
		info: linkInfo{
			linkType: linkType,
			local:    local,
			remote:   remote,
		},
		incoming: incoming,
		force:    force,
	}
	intf.writer.intf = &intf
	intf.writer.worker = make(chan [][]byte, 1)
	intf.reader.intf = &intf
	intf.reader.err = make(chan error)
	return &intf, nil
}

func (l *links) stop() error {
	close(l.stopped)
	if err := l.tcp.stop(); err != nil {
		return err
	}
	return nil
}

func (intf *link) handler() error {
	// TODO split some of this into shorter functions, so it's easier to read, and for the FIXME duplicate peer issue mentioned later
	go func() {
		for bss := range intf.writer.worker {
			intf.msgIO.writeMsgs(bss)
		}
	}()
	defer intf.writer.Act(nil, func() {
		intf.writer.closed = true
		close(intf.writer.worker)
	})
	myLinkPub, myLinkPriv := crypto.NewBoxKeys()
	meta := version_getBaseMetadata()
	meta.box = intf.links.core.boxPub
	meta.sig = intf.links.core.sigPub
	meta.link = *myLinkPub
	metaBytes := meta.encode()
	// TODO timeouts on send/recv (goroutine for send/recv, channel select w/ timer)
	var err error
	if !util.FuncTimeout(func() { err = intf.msgIO._sendMetaBytes(metaBytes) }, 30*time.Second) {
		return errors.New("timeout on metadata send")
	}
	if err != nil {
		return err
	}
	if !util.FuncTimeout(func() { metaBytes, err = intf.msgIO._recvMetaBytes() }, 30*time.Second) {
		return errors.New("timeout on metadata recv")
	}
	if err != nil {
		return err
	}
	meta = version_metadata{}
	if !meta.decode(metaBytes) || !meta.check() {
		return errors.New("failed to decode metadata")
	}
	base := version_getBaseMetadata()
	if meta.ver > base.ver || meta.ver == base.ver && meta.minorVer > base.minorVer {
		intf.links.core.log.Errorln("Failed to connect to node: " + intf.lname + " version: " + fmt.Sprintf("%d.%d", meta.ver, meta.minorVer))
		return errors.New("failed to connect: wrong version")
	}
	// Check if the remote side matches the keys we expected. This is a bit of a weak
	// check - in future versions we really should check a signature or something like that.
	if pinned := intf.options.pinnedCurve25519Keys; pinned != nil {
		if _, allowed := pinned[meta.box]; !allowed {
			intf.links.core.log.Errorf("Failed to connect to node: %q sent curve25519 key that does not match pinned keys", intf.name)
			return fmt.Errorf("failed to connect: host sent curve25519 key that does not match pinned keys")
		}
	}
	if pinned := intf.options.pinnedEd25519Keys; pinned != nil {
		if _, allowed := pinned[meta.sig]; !allowed {
			intf.links.core.log.Errorf("Failed to connect to node: %q sent ed25519 key that does not match pinned keys", intf.name)
			return fmt.Errorf("failed to connect: host sent ed25519 key that does not match pinned keys")
		}
	}
	// Check if we're authorized to connect to this key / IP
	if intf.incoming && !intf.force && !intf.links.core.peers.isAllowedEncryptionPublicKey(&meta.box) {
		intf.links.core.log.Warnf("%s connection from %s forbidden: AllowedEncryptionPublicKeys does not contain key %s",
			strings.ToUpper(intf.info.linkType), intf.info.remote, hex.EncodeToString(meta.box[:]))
		intf.msgIO.close()
		return nil
	}
	// Check if we already have a link to this node
	intf.info.box = meta.box
	intf.info.sig = meta.sig
	intf.links.mutex.Lock()
	if oldIntf, isIn := intf.links.links[intf.info]; isIn {
		intf.links.mutex.Unlock()
		// FIXME we should really return an error and let the caller block instead
		// That lets them do things like close connections on its own, avoid printing a connection message in the first place, etc.
		intf.links.core.log.Debugln("DEBUG: found existing interface for", intf.name)
		intf.msgIO.close()
		if !intf.incoming {
			// Block outgoing connection attempts until the existing connection closes
			<-oldIntf.closed
		}
		return nil
	} else {
		intf.closed = make(chan struct{})
		intf.links.links[intf.info] = intf
		defer func() {
			intf.links.mutex.Lock()
			delete(intf.links.links, intf.info)
			intf.links.mutex.Unlock()
			close(intf.closed)
		}()
		intf.links.core.log.Debugln("DEBUG: registered interface for", intf.name)
	}
	intf.links.mutex.Unlock()
	// Create peer
	shared := crypto.GetSharedKey(myLinkPriv, &meta.link)
	phony.Block(&intf.links.core.peers, func() {
		// FIXME don't use phony.Block, it's bad practice, even if it's safe here
		intf.peer = intf.links.core.peers._newPeer(&meta.box, &meta.sig, shared, intf)
	})
	if intf.peer == nil {
		return errors.New("failed to create peer")
	}
	defer func() {
		// More cleanup can go here
		intf.Act(nil, func() {
			intf.shutdown = true
			intf.peer.Act(intf, intf.peer._removeSelf)
		})
	}()
	themAddr := address.AddrForNodeID(crypto.GetNodeID(&intf.info.box))
	themAddrString := net.IP(themAddr[:]).String()
	themString := fmt.Sprintf("%s@%s", themAddrString, intf.info.remote)
	intf.links.core.log.Infof("Connected %s: %s, source %s",
		strings.ToUpper(intf.info.linkType), themString, intf.info.local)
	// Start things
	go intf.peer.start()
	intf.Act(nil, intf._notifyIdle)
	intf.reader.Act(nil, intf.reader._read)
	// Wait for the reader to finish
	// TODO find a way to do this without keeping live goroutines around
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-intf.links.stopped:
			intf.msgIO.close()
		case <-done:
		}
	}()
	err = <-intf.reader.err
	// TODO don't report an error if it's just a 'use of closed network connection'
	if err != nil {
		intf.links.core.log.Infof("Disconnected %s: %s, source %s; error: %s",
			strings.ToUpper(intf.info.linkType), themString, intf.info.local, err)
	} else {
		intf.links.core.log.Infof("Disconnected %s: %s, source %s",
			strings.ToUpper(intf.info.linkType), themString, intf.info.local)
	}
	return err
}

////////////////////////////////////////////////////////////////////////////////

// link needs to match the linkInterface type needed by the peers

type linkInterface interface {
	out([][]byte)
	linkOut([]byte)
	close()
	// These next ones are only used by the API
	name() string
	local() string
	remote() string
	interfaceType() string
}

func (intf *link) out(bss [][]byte) {
	intf.Act(nil, func() {
		// nil to prevent it from blocking if the link is somehow frozen
		// this is safe because another packet won't be sent until the link notifies
		//  the peer that it's ready for one
		intf.writer.sendFrom(nil, bss)
	})
}

func (intf *link) linkOut(bs []byte) {
	intf.Act(nil, func() {
		// nil to prevent it from blocking if the link is somehow frozen
		// FIXME this is hypothetically not safe, the peer shouldn't be sending
		//  additional packets until this one finishes, otherwise this could leak
		//  memory if writing happens slower than link packets are generated...
		//  that seems unlikely, so it's a lesser evil than deadlocking for now
		intf.writer.sendFrom(nil, [][]byte{bs})
	})
}

func (intf *link) close() {
	intf.Act(nil, func() { intf.msgIO.close() })
}

func (intf *link) name() string {
	return intf.lname
}

func (intf *link) local() string {
	return intf.info.local
}

func (intf *link) remote() string {
	return intf.info.remote
}

func (intf *link) interfaceType() string {
	return intf.info.linkType
}

////////////////////////////////////////////////////////////////////////////////
const (
	sendTime      = 1 * time.Second    // How long to wait before deciding a send is blocked
	keepAliveTime = 2 * time.Second    // How long to wait before sending a keep-alive response if we have no real traffic to send
	stallTime     = 6 * time.Second    // How long to wait for response traffic before deciding the connection has stalled
	closeTime     = 2 * switch_timeout // How long to wait before closing the link
)

// notify the intf that we're currently sending
func (intf *link) notifySending(size int) {
	intf.Act(&intf.writer, func() {
		intf.sendTimer = time.AfterFunc(sendTime, intf.notifyBlockedSend)
		if intf.keepAliveTimer != nil {
			intf.keepAliveTimer.Stop()
			intf.keepAliveTimer = nil
		}
		intf.peer.notifyBlocked(intf)
	})
}

// This gets called from a time.AfterFunc, and notifies the switch that we appear
// to have gotten blocked on a write, so the switch should start routing traffic
// through other links, if alternatives exist
func (intf *link) notifyBlockedSend() {
	intf.Act(nil, func() {
		if intf.sendTimer != nil {
			//As far as we know, we're still trying to send, and the timer fired.
			intf.sendTimer.Stop()
			intf.sendTimer = nil
			if !intf.shutdown && intf.writeUnblocked {
				intf.writeUnblocked = false
				intf.links.core.switchTable.blockPeer(intf, intf.peer.port, true)
			}
		}
	})
}

// notify the intf that we've finished sending, returning the peer to the switch
func (intf *link) notifySent(size int) {
	intf.Act(&intf.writer, func() {
		if intf.sendTimer != nil {
			intf.sendTimer.Stop()
			intf.sendTimer = nil
		}
		if intf.keepAliveTimer != nil {
			// TODO? unset this when we start sending, not when we finish...
			intf.keepAliveTimer.Stop()
			intf.keepAliveTimer = nil
		}
		intf._notifyIdle()
		if size > 0 && intf.stallTimer == nil {
			intf.stallTimer = time.AfterFunc(stallTime, intf.notifyStalled)
		}
		if !intf.shutdown && !intf.writeUnblocked {
			intf.writeUnblocked = true
			intf.links.core.switchTable.unblockPeer(intf, intf.peer.port, true)
		}
	})
}

// Notify the peer that we're ready for more traffic
func (intf *link) _notifyIdle() {
	intf.peer.Act(intf, intf.peer._handleIdle)
}

// Set the peer as stalled, to prevent them from returning to the switch until a read succeeds
func (intf *link) notifyStalled() {
	intf.Act(nil, func() { // Sent from a time.AfterFunc
		if intf.stallTimer != nil {
			intf.stallTimer.Stop()
			intf.stallTimer = nil
			if !intf.shutdown && intf.readUnblocked {
				intf.readUnblocked = false
				intf.links.core.switchTable.blockPeer(intf, intf.peer.port, false)
			}
		}
	})
}

// reset the close timer
func (intf *link) notifyReading() {
	intf.Act(&intf.reader, func() {
		if intf.closeTimer != nil {
			intf.closeTimer.Stop()
		}
		intf.closeTimer = time.AfterFunc(closeTime, func() { intf.msgIO.close() })
	})
}

// wake up the link if it was stalled, and (if size > 0) prepare to send keep-alive traffic
func (intf *link) notifyRead(size int) {
	intf.Act(&intf.reader, func() {
		if intf.stallTimer != nil {
			intf.stallTimer.Stop()
			intf.stallTimer = nil
		}
		if size > 0 && intf.keepAliveTimer == nil {
			intf.keepAliveTimer = time.AfterFunc(keepAliveTime, intf.notifyDoKeepAlive)
		}
		if !intf.shutdown && !intf.readUnblocked {
			intf.readUnblocked = true
			intf.links.core.switchTable.unblockPeer(intf, intf.peer.port, false)
		}
	})
}

// We need to send keep-alive traffic now
func (intf *link) notifyDoKeepAlive() {
	intf.Act(nil, func() { // Sent from a time.AfterFunc
		if intf.keepAliveTimer != nil {
			intf.keepAliveTimer.Stop()
			intf.keepAliveTimer = nil
			intf.writer.sendFrom(nil, [][]byte{nil}) // Empty keep-alive traffic
		}
	})
}

////////////////////////////////////////////////////////////////////////////////

type linkWriter struct {
	phony.Inbox
	intf   *link
	worker chan [][]byte
	closed bool
}

func (w *linkWriter) sendFrom(from phony.Actor, bss [][]byte) {
	w.Act(from, func() {
		if w.closed {
			return
		}
		var size int
		for _, bs := range bss {
			size += len(bs)
		}
		w.intf.notifySending(size)
		w.worker <- bss
		w.intf.notifySent(size)
	})
}

////////////////////////////////////////////////////////////////////////////////

type linkReader struct {
	phony.Inbox
	intf *link
	err  chan error
}

func (r *linkReader) _read() {
	r.intf.notifyReading()
	msg, err := r.intf.msgIO.readMsg()
	r.intf.notifyRead(len(msg))
	if len(msg) > 0 {
		r.intf.peer.handlePacketFrom(r, msg)
	}
	if err != nil {
		if err != io.EOF {
			r.err <- err
		}
		close(r.err)
		return
	}
	// Now try to read again
	r.Act(nil, r._read)
}
