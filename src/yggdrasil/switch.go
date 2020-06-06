package yggdrasil

// This part constructs a spanning tree of the network
// It routes packets based on distance on the spanning tree
//  In general, this is *not* equivalent to routing on the tree
//  It falls back to the tree in the worst case, but it can take shortcuts too
// This is the part that makes routing reasonably efficient on scale-free graphs

// TODO document/comment everything in a lot more detail

// TODO? use a pre-computed lookup table (python version had this)
//  A little annoying to do with constant changes from backpressure

import (
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/crypto"

	"github.com/Arceliar/phony"
)

const (
	switch_timeout          = time.Minute
	switch_updateInterval   = switch_timeout / 2
	switch_throttle         = switch_updateInterval / 2
	switch_faster_threshold = 240 //Number of switch updates before switching to a faster parent
)

// The switch locator represents the topology and network state dependent info about a node, minus the signatures that go with it.
// Nodes will pick the best root they see, provided that the root continues to push out updates with new timestamps.
// The coords represent a path from the root to a node.
// This path is generally part of a spanning tree, except possibly the last hop (it can loop when sending coords to your parent, but they see this and know not to use a looping path).
type switchLocator struct {
	root   crypto.SigPubKey
	tstamp int64
	coords []switchPort
}

// Returns true if the first sigPubKey has a higher TreeID.
func firstIsBetter(first, second *crypto.SigPubKey) bool {
	// Higher TreeID is better
	ftid := crypto.GetTreeID(first)
	stid := crypto.GetTreeID(second)
	for idx := 0; idx < len(ftid); idx++ {
		if ftid[idx] == stid[idx] {
			continue
		}
		return ftid[idx] > stid[idx]
	}
	// Edge case, when comparing identical IDs
	return false
}

// Returns a copy of the locator which can safely be mutated.
func (l *switchLocator) clone() switchLocator {
	// Used to create a deep copy for use in messages
	// Copy required because we need to mutate coords before sending
	// (By appending the port from us to the destination)
	loc := *l
	loc.coords = make([]switchPort, len(l.coords), len(l.coords)+1)
	copy(loc.coords, l.coords)
	return loc
}

// Gets the distance a locator is from the provided destination coords, with the coords provided in []byte format (used to compress integers sent over the wire).
func (l *switchLocator) dist(dest []byte) int {
	// Returns distance (on the tree) from these coords
	offset := 0
	fdc := 0
	for {
		if fdc >= len(l.coords) {
			break
		}
		coord, length := wire_decode_uint64(dest[offset:])
		if length == 0 {
			break
		}
		if l.coords[fdc] != switchPort(coord) {
			break
		}
		fdc++
		offset += length
	}
	dist := len(l.coords[fdc:])
	for {
		_, length := wire_decode_uint64(dest[offset:])
		if length == 0 {
			break
		}
		dist++
		offset += length
	}
	return dist
}

func (l *switchLocator) ldist(sl *switchLocator) int {
	lca := -1
	for idx := 0; idx < len(l.coords); idx++ {
		if idx >= len(sl.coords) {
			break
		}
		if l.coords[idx] != sl.coords[idx] {
			break
		}
		lca = idx
	}
	return len(l.coords) + len(sl.coords) - 2*(lca+1)
}

// Gets coords in wire encoded format, with *no* length prefix.
func (l *switchLocator) getCoords() []byte {
	bs := make([]byte, 0, len(l.coords))
	for _, coord := range l.coords {
		c := wire_encode_uint64(uint64(coord))
		bs = append(bs, c...)
	}
	return bs
}

// Returns true if this locator represents an ancestor of the locator given as an argument.
// Ancestor means that it's the parent node, or the parent of parent, and so on...
func (x *switchLocator) isAncestorOf(y *switchLocator) bool {
	if x.root != y.root {
		return false
	}
	if len(x.coords) > len(y.coords) {
		return false
	}
	for idx := range x.coords {
		if x.coords[idx] != y.coords[idx] {
			return false
		}
	}
	return true
}

// Information about a peer, used by the switch to build the tree and eventually make routing decisions.
type peerInfo struct {
	key        crypto.SigPubKey      // ID of this peer
	locator    switchLocator         // Should be able to respond with signatures upon request
	degree     uint64                // Self-reported degree
	time       time.Time             // Time this node was last seen
	faster     map[switchPort]uint64 // Counter of how often a node is faster than the current parent, penalized extra if slower
	port       switchPort            // Interface number of this peer
	msg        switchMsg             // The wire switchMsg used
	readBlock  bool                  // True if the link notified us of a read that blocked too long
	writeBlock bool                  // True of the link notified us of a write that blocked too long
}

func (pinfo *peerInfo) blocked() bool {
	return pinfo.readBlock || pinfo.writeBlock
}

// This is just a uint64 with a named type for clarity reasons.
type switchPort uint64

// This is the subset of the information about a peer needed to make routing decisions, and it stored separately in an atomically accessed table, which gets hammered in the "hot loop" of the routing logic (see: peer.handleTraffic in peers.go).
type tableElem struct {
	port    switchPort
	locator switchLocator
	time    time.Time
	next    map[switchPort]*tableElem
}

// This is the subset of the information about all peers needed to make routing decisions, and it stored separately in an atomically accessed table, which gets hammered in the "hot loop" of the routing logic (see: peer.handleTraffic in peers.go).
type lookupTable struct {
	self   switchLocator
	elems  map[switchPort]tableElem // all switch peers, just for sanity checks + API/debugging
	_start tableElem                // used for lookups
	_msg   switchMsg
}

// This is switch information which is mutable and needs to be modified by other goroutines, but is not accessed atomically.
// Use the switchTable functions to access it safely using the RWMutex for synchronization.
type switchData struct {
	// All data that's mutable and used by exported Table methods
	// To be read/written with atomic.Value Store/Load calls
	locator switchLocator
	peers   map[switchPort]peerInfo
	msg     *switchMsg
}

// All the information stored by the switch.
type switchTable struct {
	core        *Core
	key         crypto.SigPubKey           // Our own key
	phony.Inbox                            // Owns the below
	time        time.Time                  // Time when locator.tstamp was last updated
	drop        map[crypto.SigPubKey]int64 // Tstamp associated with a dropped root
	parent      switchPort                 // Port of whatever peer is our parent, or self if we're root
	data        switchData                 //
}

// Minimum allowed total size of switch queues.
const SwitchQueueTotalMinSize = 4 * 1024 * 1024

// Initializes the switchTable struct.
func (t *switchTable) init(core *Core) {
	now := time.Now()
	t.core = core
	t.key = t.core.sigPub
	locator := switchLocator{root: t.key, tstamp: now.Unix()}
	peers := make(map[switchPort]peerInfo)
	t.data = switchData{locator: locator, peers: peers}
	t.drop = make(map[crypto.SigPubKey]int64)
	phony.Block(t, t._updateTable)
}

func (t *switchTable) reconfigure() {
	// This is where reconfiguration would go, if we had anything useful to do.
	t.core.links.reconfigure()
	t.core.peers.reconfigure()
}

// Regular maintenance to possibly timeout/reset the root and similar.
func (t *switchTable) doMaintenance(from phony.Actor) {
	t.Act(from, func() {
		// Periodic maintenance work to keep things internally consistent
		t._cleanRoot()
		t._cleanDropped()
	})
}

// Updates the root periodically if it is ourself, or promotes ourself to root if we're better than the current root or if the current root has timed out.
func (t *switchTable) _cleanRoot() {
	// TODO rethink how this is done?...
	// Get rid of the root if it looks like its timed out
	now := time.Now()
	doUpdate := false
	if now.Sub(t.time) > switch_timeout {
		dropped := t.data.peers[t.parent]
		dropped.time = t.time
		t.drop[t.data.locator.root] = t.data.locator.tstamp
		doUpdate = true
	}
	// Or, if we're better than our root, root ourself
	if firstIsBetter(&t.key, &t.data.locator.root) {
		doUpdate = true
	}
	// Or, if we are the root, possibly update our timestamp
	if t.data.locator.root == t.key &&
		now.Sub(t.time) > switch_updateInterval {
		doUpdate = true
	}
	if doUpdate {
		t.parent = switchPort(0)
		t.time = now
		if t.data.locator.root != t.key {
			defer t.core.router.reset(nil)
		}
		t.data.locator = switchLocator{root: t.key, tstamp: now.Unix()}
		t._updateTable() // updates base copy of switch msg in lookupTable
		t.core.peers.sendSwitchMsgs(t)
	}
}

// Blocks and, if possible, unparents a peer
func (t *switchTable) blockPeer(from phony.Actor, port switchPort, isWrite bool) {
	t.Act(from, func() {
		peer, isIn := t.data.peers[port]
		switch {
		case isIn && !isWrite && !peer.readBlock:
			peer.readBlock = true
		case isIn && isWrite && !peer.writeBlock:
			peer.writeBlock = true
		default:
			return
		}
		t.data.peers[port] = peer
		defer t._updateTable()
		if port != t.parent {
			return
		}
		t.parent = 0
		for _, info := range t.data.peers {
			if info.port == port {
				continue
			}
			t._handleMsg(&info.msg, info.port, true)
		}
		t._handleMsg(&peer.msg, peer.port, true)
	})
}

func (t *switchTable) unblockPeer(from phony.Actor, port switchPort, isWrite bool) {
	t.Act(from, func() {
		peer, isIn := t.data.peers[port]
		switch {
		case isIn && !isWrite && peer.readBlock:
			peer.readBlock = false
		case isIn && isWrite && peer.writeBlock:
			peer.writeBlock = false
		default:
			return
		}
		t.data.peers[port] = peer
		t._updateTable()
	})
}

// Removes a peer.
// Must be called by the router actor with a lambda that calls this.
// If the removed peer was this node's parent, it immediately tries to find a new parent.
func (t *switchTable) forgetPeer(from phony.Actor, port switchPort) {
	t.Act(from, func() {
		delete(t.data.peers, port)
		defer t._updateTable()
		if port != t.parent {
			return
		}
		t.parent = 0
		for _, info := range t.data.peers {
			t._handleMsg(&info.msg, info.port, true)
		}
	})
}

// Dropped is a list of roots that are better than the current root, but stopped sending new timestamps.
// If we switch to a new root, and that root is better than an old root that previously timed out, then we can clean up the old dropped root infos.
// This function is called periodically to do that cleanup.
func (t *switchTable) _cleanDropped() {
	// TODO? only call this after root changes, not periodically
	for root := range t.drop {
		if !firstIsBetter(&root, &t.data.locator.root) {
			delete(t.drop, root)
		}
	}
}

// A switchMsg contains the root node's sig key, timestamp, and signed per-hop information about a path from the root node to some other node in the network.
// This is exchanged with peers to construct the spanning tree.
// A subset of this information, excluding the signatures, is used to construct locators that are used elsewhere in the code.
type switchMsg struct {
	Root   crypto.SigPubKey
	TStamp int64
	Hops   []switchMsgHop
}

// This represents the signed information about the path leading from the root the Next node, via the Port specified here.
type switchMsgHop struct {
	Port switchPort
	Next crypto.SigPubKey
	Sig  crypto.SigBytes
}

// This returns a *switchMsg to a copy of this node's current switchMsg, which can safely have additional information appended to Hops and sent to a peer.
func (t *switchTable) _getMsg() *switchMsg {
	if t.parent == 0 {
		return &switchMsg{Root: t.key, TStamp: t.data.locator.tstamp}
	} else if parent, isIn := t.data.peers[t.parent]; isIn {
		msg := parent.msg
		msg.Hops = append([]switchMsgHop(nil), msg.Hops...)
		return &msg
	} else {
		return nil
	}
}

func (t *lookupTable) getMsg() *switchMsg {
	msg := t._msg
	msg.Hops = append([]switchMsgHop(nil), t._msg.Hops...)
	return &msg
}

// This function checks that the root information in a switchMsg is OK.
// In particular, that the root is better, or else the same as the current root but with a good timestamp, and that this root+timestamp haven't been dropped due to timeout.
func (t *switchTable) _checkRoot(msg *switchMsg) bool {
	// returns false if it's a dropped root, not a better root, or has an older timestamp
	// returns true otherwise
	// used elsewhere to keep inserting peers into the dht only if root info is OK
	dropTstamp, isIn := t.drop[msg.Root]
	switch {
	case isIn && dropTstamp >= msg.TStamp:
		return false
	case firstIsBetter(&msg.Root, &t.data.locator.root):
		return true
	case t.data.locator.root != msg.Root:
		return false
	case t.data.locator.tstamp > msg.TStamp:
		return false
	default:
		return true
	}
}

// This updates the switch with information about a peer.
// Then the tricky part, it decides if it should update our own locator as a result.
// That happens if this node is already our parent, or is advertising a better root, or is advertising a better path to the same root, etc...
// There are a lot of very delicate order sensitive checks here, so its' best to just read the code if you need to understand what it's doing.
// It's very important to not change the order of the statements in the case function unless you're absolutely sure that it's safe, including safe if used alongside nodes that used the previous order.
// Set the third arg to true if you're reprocessing an old message, e.g. to find a new parent after one disconnects, to avoid updating some timing related things.
func (t *switchTable) _handleMsg(msg *switchMsg, fromPort switchPort, reprocessing bool) {
	// TODO directly use a switchMsg instead of switchMessage + sigs
	now := time.Now()
	// Set up the sender peerInfo
	var sender peerInfo
	sender.locator.root = msg.Root
	sender.locator.tstamp = msg.TStamp
	prevKey := msg.Root
	for _, hop := range msg.Hops {
		// Build locator
		sender.locator.coords = append(sender.locator.coords, hop.Port)
		sender.key = prevKey
		prevKey = hop.Next
	}
	if sender.key == t.key {
		return // Don't peer with ourself via different interfaces
	}
	sender.msg = *msg
	sender.port = fromPort
	sender.time = now
	// Decide what to do
	equiv := func(x *switchLocator, y *switchLocator) bool {
		if x.root != y.root {
			return false
		}
		if len(x.coords) != len(y.coords) {
			return false
		}
		for idx := range x.coords {
			if x.coords[idx] != y.coords[idx] {
				return false
			}
		}
		return true
	}
	doUpdate := false
	oldSender := t.data.peers[fromPort]
	if !equiv(&sender.locator, &oldSender.locator) {
		// Reset faster info, we'll start refilling it right after this
		sender.faster = nil
		doUpdate = true
	}
	// Update the matrix of peer "faster" thresholds
	if reprocessing {
		sender.faster = oldSender.faster
		sender.time = oldSender.time
		sender.readBlock = oldSender.readBlock
		sender.writeBlock = oldSender.writeBlock
	} else {
		sender.faster = make(map[switchPort]uint64, len(oldSender.faster))
		for port, peer := range t.data.peers {
			if port == fromPort {
				continue
			} else if sender.locator.root != peer.locator.root || sender.locator.tstamp > peer.locator.tstamp {
				// We were faster than this node, so increment, as long as we don't overflow because of it
				if oldSender.faster[peer.port] < switch_faster_threshold {
					sender.faster[port] = oldSender.faster[peer.port] + 1
				} else {
					sender.faster[port] = switch_faster_threshold
				}
			} else {
				// Slower than this node, penalize (more than the reward amount)
				if oldSender.faster[port] > 1 {
					sender.faster[port] = oldSender.faster[peer.port] - 2
				} else {
					sender.faster[port] = 0
				}
			}
		}
	}
	if sender.blocked() != oldSender.blocked() {
		doUpdate = true
	}
	// Update sender
	t.data.peers[fromPort] = sender
	// Decide if we should also update our root info to make the sender our parent
	updateRoot := false
	oldParent, isIn := t.data.peers[t.parent]
	noParent := !isIn
	noLoop := func() bool {
		for idx := 0; idx < len(msg.Hops)-1; idx++ {
			if msg.Hops[idx].Next == t.core.sigPub {
				return false
			}
		}
		if sender.locator.root == t.core.sigPub {
			return false
		}
		return true
	}()
	dropTstamp, isIn := t.drop[sender.locator.root]
	// Decide if we need to update info about the root or change parents.
	switch {
	case !noLoop:
		// This route loops, so we can't use the sender as our parent.
	case isIn && dropTstamp >= sender.locator.tstamp:
		// This is a known root with a timestamp older than a known timeout, so we can't trust it to be a new announcement.
	case firstIsBetter(&sender.locator.root, &t.data.locator.root):
		// This is a better root than what we're currently using, so we should update.
		updateRoot = true
	case t.data.locator.root != sender.locator.root:
		// This is not the same root, and it's apparently not better (from the above), so we should ignore it.
	case t.data.locator.tstamp > sender.locator.tstamp:
		// This timetsamp is older than the most recently seen one from this root, so we should ignore it.
	case noParent:
		// We currently have no working parent, and at this point in the switch statement, anything is better than nothing.
		updateRoot = true
	case sender.faster[t.parent] >= switch_faster_threshold:
		// The is reliably faster than the current parent.
		updateRoot = true
	case !sender.blocked() && oldParent.blocked():
		// Replace a blocked parent
		updateRoot = true
	case reprocessing && sender.blocked() && !oldParent.blocked():
		// Don't replace an unblocked parent when reprocessing
	case reprocessing && sender.faster[t.parent] > oldParent.faster[sender.port]:
		// The sender seems to be reliably faster than the current parent, so switch to them instead.
		updateRoot = true
	case sender.port != t.parent:
		// Ignore further cases if the sender isn't our parent.
	case !reprocessing && !equiv(&sender.locator, &t.data.locator):
		// Special case:
		// If coords changed, then we need to penalize this node somehow, to prevent flapping.
		// First, reset all faster-related info to 0.
		// Then, de-parent the node and reprocess all messages to find a new parent.
		t.parent = 0
		for _, peer := range t.data.peers {
			if peer.port == sender.port {
				continue
			}
			t._handleMsg(&peer.msg, peer.port, true)
		}
		// Process the sender last, to avoid keeping them as a parent if at all possible.
		t._handleMsg(&sender.msg, sender.port, true)
	case now.Sub(t.time) < switch_throttle:
		// We've already gotten an update from this root recently, so ignore this one to avoid flooding.
	case sender.locator.tstamp > t.data.locator.tstamp:
		// The timestamp was updated, so we need to update locally and send to our peers.
		updateRoot = true
	}
	// Note that we depend on the LIFO order of the stack of defers here...
	if updateRoot {
		doUpdate = true
		if !equiv(&sender.locator, &t.data.locator) {
			defer t.core.router.reset(t)
		}
		if t.data.locator.tstamp != sender.locator.tstamp {
			t.time = now
		}
		t.data.locator = sender.locator
		t.parent = sender.port
		defer t.core.peers.sendSwitchMsgs(t)
	}
	if doUpdate {
		t._updateTable()
	}
	return
}

////////////////////////////////////////////////////////////////////////////////

// The rest of these are related to the switch lookup table

func (t *switchTable) _updateTable() {
	newTable := lookupTable{
		self:  t.data.locator.clone(),
		elems: make(map[switchPort]tableElem, len(t.data.peers)),
		_msg:  *t._getMsg(),
	}
	newTable._init()
	for _, pinfo := range t.data.peers {
		if pinfo.blocked() || pinfo.locator.root != newTable.self.root {
			continue
		}
		loc := pinfo.locator.clone()
		loc.coords = loc.coords[:len(loc.coords)-1] // Remove the them->self link
		elem := tableElem{
			locator: loc,
			port:    pinfo.port,
			time:    pinfo.time,
		}
		newTable._insert(&elem)
		newTable.elems[pinfo.port] = elem
	}
	t.core.peers.updateTables(t, &newTable)
	t.core.router.updateTable(t, &newTable)
}

func (t *lookupTable) _init() {
	// WARNING: this relies on the convention that the self port is 0
	self := tableElem{locator: t.self} // create self elem
	t._start = self                    // initialize _start to self
	t._insert(&self)                   // insert self into table
}

func (t *lookupTable) _insert(elem *tableElem) {
	// This is a helper that should only be run during _updateTable
	here := &t._start
	for idx := 0; idx <= len(elem.locator.coords); idx++ {
		refLoc := here.locator
		refLoc.coords = refLoc.coords[:idx] // Note that this is length idx (starts at length 0)
		oldDist := refLoc.ldist(&here.locator)
		newDist := refLoc.ldist(&elem.locator)
		var update bool
		switch {
		case newDist < oldDist: // new elem is closer to this point in the tree
			update = true
		case newDist > oldDist: // new elem is too far
		case elem.locator.tstamp > refLoc.tstamp: // new elem has a closer timestamp
			update = true
		case elem.locator.tstamp < refLoc.tstamp: // new elem's timestamp is too old
		case elem.time.Before(here.time): // same dist+timestamp, but new elem delivered it faster
			update = true
		}
		if update {
			here.port = elem.port
			here.locator = elem.locator
			here.time = elem.time
			// Problem: here is a value, so this doesn't actually update anything...
		}
		if idx < len(elem.locator.coords) {
			if here.next == nil {
				here.next = make(map[switchPort]*tableElem)
			}
			var next *tableElem
			var ok bool
			if next, ok = here.next[elem.locator.coords[idx]]; !ok {
				nextVal := *elem
				next = &nextVal
				here.next[next.locator.coords[idx]] = next
			}
			here = next
		}
	}
}

// Starts the switch worker
func (t *switchTable) start() error {
	t.core.log.Infoln("Starting switch")
	// There's actually nothing to do to start it...
	return nil
}

func (t *lookupTable) lookup(coords []byte) switchPort {
	var offset int
	here := &t._start
	for offset < len(coords) {
		port, l := wire_decode_uint64(coords[offset:])
		offset += l
		if next, ok := here.next[switchPort(port)]; ok {
			here = next
		} else {
			break
		}
	}
	return here.port
}
