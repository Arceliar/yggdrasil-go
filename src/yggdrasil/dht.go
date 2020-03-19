package yggdrasil

// A chord-like Distributed Hash Table (DHT).
// Used to look up coords given a NodeID and bitmask (taken from an IPv6 address).
// Keeps track of immediate successor, predecessor, and all peers.
// Also keeps track of other nodes if they're closer in tree space than all other known nodes encountered when heading in either direction to that point, under the hypothesis that, for the kinds of networks we care about, this should probabilistically include the node needed to keep lookups to near O(logn) steps.

import (
	"sort"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/crypto"
)

const (
	dht_lookup_size     = 16
	dht_timeout         = 6 * time.Minute
	dht_max_delay       = 5 * time.Minute
	dht_max_delay_dirty = 30 * time.Second
)

// dhtInfo represents everything we know about a node in the DHT.
// This includes its key, a cache of its NodeID, coords, and timing/ping related info for deciding who/when to ping nodes for maintenance.
type dhtInfo struct {
	nodeID_hidden *crypto.NodeID
	key           crypto.BoxPubKey
	coords        []byte
	recv          time.Time // When we last received a message
	pings         int       // Time out if at least 3 consecutive maintenance pings drop
	throttle      time.Duration
	dirty         bool // Set to true if we've used this node in ping responses (for queries about someone other than the person doing the asking, i.e. real searches) since the last time we heard from the node
}

// Returns the *NodeID associated with dhtInfo.key, calculating it on the fly the first time or from a cache all subsequent times.
func (info *dhtInfo) getNodeID() *crypto.NodeID {
	if info.nodeID_hidden == nil {
		info.nodeID_hidden = crypto.GetNodeID(&info.key)
	}
	return info.nodeID_hidden
}

// Request for a node to do a lookup.
// Includes our key and coords so they can send a response back, and the destination NodeID we want to ask about.
type dhtReq struct {
	Key    crypto.BoxPubKey // Key of whoever asked
	Coords []byte           // Coords of whoever asked
	Dest   crypto.NodeID    // NodeID they're asking about
}

// Response to a DHT lookup.
// Includes the key and coords of the node that's responding, and the destination they were asked about.
// The main part is Infos []*dhtInfo, the lookup response.
type dhtRes struct {
	Key    crypto.BoxPubKey // key of the sender
	Coords []byte           // coords of the sender
	Dest   crypto.NodeID
	Infos  []*dhtInfo // response
}

// Parts of a DHT req usable as a key in a map.
type dhtReqKey struct {
	key  crypto.BoxPubKey
	dest crypto.NodeID
}

// The main DHT struct.
type dht struct {
	router    *router
	nodeID    crypto.NodeID
	reqs      map[dhtReqKey]time.Time          // Keeps track of recent outstanding requests
	callbacks map[dhtReqKey][]dht_callbackInfo // Search and admin lookup callbacks
	// These next two could be replaced by a single linked list or similar...
	table map[crypto.NodeID]*dhtInfo
	imp   []*dhtInfo
}

// Initializes the DHT.
func (t *dht) init(r *router) {
	t.router = r
	t.nodeID = *t.router.core.NodeID()
	t.callbacks = make(map[dhtReqKey][]dht_callbackInfo)
	t.reset()
}

func (t *dht) reconfigure() {
	// This is where reconfiguration would go, if we had anything to do
}

// Resets the DHT in response to coord changes.
// This empties all info from the DHT and drops outstanding requests.
func (t *dht) reset() {
	t.reqs = make(map[dhtReqKey]time.Time)
	t.table = make(map[crypto.NodeID]*dhtInfo)
	t.imp = nil
}

// Does a DHT lookup and returns up to dht_lookup_size results.
func (t *dht) lookup(nodeID *crypto.NodeID, everything bool) []*dhtInfo {
	results := make([]*dhtInfo, 0, len(t.table))
	for _, info := range t.table {
		results = append(results, info)
	}
	if len(results) > dht_lookup_size {
		// Drop the middle part, so we keep some nodes before and after.
		// This should help to bootstrap / recover more quickly.
		sort.SliceStable(results, func(i, j int) bool {
			return dht_ordered(nodeID, results[i].getNodeID(), results[j].getNodeID())
		})
		newRes := make([]*dhtInfo, 0, len(results))
		newRes = append(newRes, results[len(results)-dht_lookup_size/2:]...)
		newRes = append(newRes, results[:len(results)-dht_lookup_size/2]...)
		results = newRes
		results = results[:dht_lookup_size]
	}
	return results
}

// Insert into table, preserving the time we last sent a packet if the node was already in the table, otherwise setting that time to now.
func (t *dht) insert(info *dhtInfo) {
	if *info.getNodeID() == t.nodeID {
		// This shouldn't happen, but don't add it if it does
		return
	}
	info.recv = time.Now()
	if oldInfo, isIn := t.table[*info.getNodeID()]; isIn {
		sameCoords := true
		if len(info.coords) != len(oldInfo.coords) {
			sameCoords = false
		} else {
			for idx := 0; idx < len(info.coords); idx++ {
				if info.coords[idx] != oldInfo.coords[idx] {
					sameCoords = false
					break
				}
			}
		}
		if sameCoords {
			info.throttle = oldInfo.throttle
		}
	}
	t.imp = nil // It needs to update to get a pointer to the new info
	t.table[*info.getNodeID()] = info
}

// Insert a peer into the table if it hasn't been pinged lately, to keep peers from dropping
func (t *dht) insertPeer(info *dhtInfo) {
	oldInfo, isIn := t.table[*info.getNodeID()]
	if !isIn || time.Since(oldInfo.recv) > dht_max_delay+30*time.Second {
		// TODO? also check coords?
		newInfo := *info // Insert a copy
		t.insert(&newInfo)
	}
}

// Return true if first/second/third are (partially) ordered correctly.
func dht_ordered(first, second, third *crypto.NodeID) bool {
	lessOrEqual := func(first, second *crypto.NodeID) bool {
		for idx := 0; idx < crypto.NodeIDLen; idx++ {
			if first[idx] > second[idx] {
				return false
			}
			if first[idx] < second[idx] {
				return true
			}
		}
		return true
	}
	firstLessThanSecond := lessOrEqual(first, second)
	secondLessThanThird := lessOrEqual(second, third)
	thirdLessThanFirst := lessOrEqual(third, first)
	switch {
	case firstLessThanSecond && secondLessThanThird:
		// Nothing wrapped around 0, the easy case
		return true
	case thirdLessThanFirst && firstLessThanSecond:
		// Third wrapped around 0
		return true
	case secondLessThanThird && thirdLessThanFirst:
		// Second (and third) wrapped around 0
		return true
	}
	return false
}

// Reads a request, performs a lookup, and responds.
// Update info about the node that sent the request.
func (t *dht) handleReq(req *dhtReq) {
	// Send them what they asked for
	loc := t.router.core.switchTable.getLocator()
	coords := loc.getCoords()
	res := dhtRes{
		Key:    t.router.core.boxPub,
		Coords: coords,
		Dest:   req.Dest,
		Infos:  t.lookup(&req.Dest, false),
	}
	t.sendRes(&res, req)
	// Also add them to our DHT
	info := dhtInfo{
		key:    req.Key,
		coords: req.Coords,
	}
	if _, isIn := t.table[*info.getNodeID()]; !isIn && t.isImportant(&info) {
		t.ping(&info, nil)
	}
	// Maybe mark nodes from lookup as dirty
	if req.Dest != *info.getNodeID() {
		// This node asked about someone other than themself, so this wasn't just idle traffic.
		for _, info := range res.Infos {
			// Mark nodes dirty so we're sure to check up on them again later
			info.dirty = true
		}
	}
}

// Sends a lookup response to the specified node.
func (t *dht) sendRes(res *dhtRes, req *dhtReq) {
	// Send a reply for a dhtReq
	bs := res.encode()
	shared := t.router.sessions.getSharedKey(&t.router.core.boxPriv, &req.Key)
	payload, nonce := crypto.BoxSeal(shared, bs, nil)
	p := wire_protoTrafficPacket{
		Coords:  req.Coords,
		ToKey:   req.Key,
		FromKey: t.router.core.boxPub,
		Nonce:   *nonce,
		Payload: payload,
	}
	packet := p.encode()
	t.router.out(packet)
}

type dht_callbackInfo struct {
	f    func(*dhtRes)
	time time.Time
}

// Adds a callback and removes it after some timeout.
func (t *dht) addCallback(rq *dhtReqKey, callback func(*dhtRes)) {
	info := dht_callbackInfo{callback, time.Now().Add(6 * time.Second)}
	t.callbacks[*rq] = append(t.callbacks[*rq], info)
}

// Reads a lookup response, checks that we had sent a matching request, and processes the response info.
// This mainly consists of updating the node we asked in our DHT (they responded, so we know they're still alive), and deciding if we want to do anything with their responses
func (t *dht) handleRes(res *dhtRes) {
	rq := dhtReqKey{res.Key, res.Dest}
	if callbacks, isIn := t.callbacks[rq]; isIn {
		for _, callback := range callbacks {
			callback.f(res)
		}
		delete(t.callbacks, rq)
	}
	_, isIn := t.reqs[rq]
	if !isIn {
		return
	}
	delete(t.reqs, rq)
	rinfo := dhtInfo{
		key:    res.Key,
		coords: res.Coords,
	}
	t.insert(&rinfo)
	for _, info := range res.Infos {
		if *info.getNodeID() == t.nodeID {
			continue
		} // Skip self
		if _, isIn := t.table[*info.getNodeID()]; isIn {
			// TODO? don't skip if coords are different?
			continue
		}
		if t.isImportant(info) {
			t.ping(info, nil)
		}
	}
}

// Sends a lookup request to the specified node.
func (t *dht) sendReq(req *dhtReq, dest *dhtInfo) {
	// Send a dhtReq to the node in dhtInfo
	bs := req.encode()
	shared := t.router.sessions.getSharedKey(&t.router.core.boxPriv, &dest.key)
	payload, nonce := crypto.BoxSeal(shared, bs, nil)
	p := wire_protoTrafficPacket{
		Coords:  dest.coords,
		ToKey:   dest.key,
		FromKey: t.router.core.boxPub,
		Nonce:   *nonce,
		Payload: payload,
	}
	packet := p.encode()
	t.router.out(packet)
	rq := dhtReqKey{dest.key, req.Dest}
	t.reqs[rq] = time.Now()
}

// Sends a lookup to this info, looking for the target.
func (t *dht) ping(info *dhtInfo, target *crypto.NodeID) {
	// Creates a req for the node at dhtInfo, asking them about the target (if one is given) or themself (if no target is given)
	if target == nil {
		target = &t.nodeID
	}
	loc := t.router.core.switchTable.getLocator()
	coords := loc.getCoords()
	req := dhtReq{
		Key:    t.router.core.boxPub,
		Coords: coords,
		Dest:   *target,
	}
	t.sendReq(&req, info)
}

// Periodic maintenance work to keep important DHT nodes alive.
func (t *dht) doMaintenance() {
	now := time.Now()
	newReqs := make(map[dhtReqKey]time.Time, len(t.reqs))
	for key, start := range t.reqs {
		if now.Sub(start) < 6*time.Second {
			newReqs[key] = start
		}
	}
	t.reqs = newReqs
	newCallbacks := make(map[dhtReqKey][]dht_callbackInfo, len(t.callbacks))
	for key, cs := range t.callbacks {
		for _, c := range cs {
			if now.Before(c.time) {
				newCallbacks[key] = append(newCallbacks[key], c)
			} else {
				// Signal failure
				c.f(nil)
			}
		}
	}
	t.callbacks = newCallbacks
	for infoID, info := range t.table {
		switch {
		case info.pings > 6:
			// It failed to respond to too many pings
			fallthrough
		case now.Sub(info.recv) > dht_timeout:
			// It's too old
			fallthrough
		case info.dirty && now.Sub(info.recv) > dht_max_delay_dirty && !t.isImportant(info):
			// We won't ping it to refresh it, so just drop it
			delete(t.table, infoID)
			t.imp = nil
		}
	}
	for _, info := range t.getImportant() {
		switch {
		case now.Sub(info.recv) > info.throttle:
			info.throttle *= 2
			if info.throttle < time.Second {
				info.throttle = time.Second
			} else if info.throttle > dht_max_delay {
				info.throttle = dht_max_delay
			}
			fallthrough
		case info.dirty && now.Sub(info.recv) > dht_max_delay_dirty:
			t.ping(info, nil)
			info.pings++
		}
	}
}

// Gets a list of important nodes, used by isImportant.
func (t *dht) getImportant() []*dhtInfo {
	if t.imp == nil {
		// Get a list of all known nodes
		infos := make([]*dhtInfo, 0, len(t.table))
		for _, info := range t.table {
			infos = append(infos, info)
		}
		// Sort them by increasing order in distance along the ring
		sort.SliceStable(infos, func(i, j int) bool {
			// Sort in order of predecessors (!), reverse from chord normal, because it plays nicer with zero bits for unknown parts of target addresses
			return dht_ordered(infos[j].getNodeID(), infos[i].getNodeID(), &t.nodeID)
		})
		// Keep the ones that are no further than the closest seen so far
		minDist := ^uint64(0)
		loc := t.router.core.switchTable.getLocator()
		important := infos[:0]
		for _, info := range infos {
			dist := uint64(loc.dist(info.coords))
			if dist < minDist {
				minDist = dist
				important = append(important, info)
			} else if len(important) < 2 {
				important = append(important, info)
			}
		}
		var temp []*dhtInfo
		minDist = ^uint64(0)
		for idx := len(infos) - 1; idx >= 0; idx-- {
			info := infos[idx]
			dist := uint64(loc.dist(info.coords))
			if dist < minDist {
				minDist = dist
				temp = append(temp, info)
			} else if len(temp) < 2 {
				temp = append(temp, info)
			}
		}
		for idx := len(temp) - 1; idx >= 0; idx-- {
			important = append(important, temp[idx])
		}
		t.imp = important
	}
	return t.imp
}

// Returns true if this is a node we need to keep track of for the DHT to work.
func (t *dht) isImportant(ninfo *dhtInfo) bool {
	if ninfo.key == t.router.core.boxPub {
		return false
	}
	important := t.getImportant()
	// Check if ninfo is of equal or greater importance to what we already know
	loc := t.router.core.switchTable.getLocator()
	ndist := uint64(loc.dist(ninfo.coords))
	minDist := ^uint64(0)
	for _, info := range important {
		if (*info.getNodeID() == *ninfo.getNodeID()) ||
			(ndist < minDist && dht_ordered(info.getNodeID(), ninfo.getNodeID(), &t.nodeID)) {
			// Either the same node, or a better one
			return true
		}
		dist := uint64(loc.dist(info.coords))
		if dist < minDist {
			minDist = dist
		}
	}
	minDist = ^uint64(0)
	for idx := len(important) - 1; idx >= 0; idx-- {
		info := important[idx]
		if (*info.getNodeID() == *ninfo.getNodeID()) ||
			(ndist < minDist && dht_ordered(&t.nodeID, ninfo.getNodeID(), info.getNodeID())) {
			// Either the same node, or a better one
			return true
		}
		dist := uint64(loc.dist(info.coords))
		if dist < minDist {
			minDist = dist
		}
	}
	// We didn't find any important node that ninfo is better than
	return false
}
