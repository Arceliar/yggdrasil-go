package yggdrasil

/*

This part has the (kademlia-like) distributed hash table

It's used to look up coords for a NodeID

Every node participates in the DHT, and the DHT stores no real keys/values
(Only the peer relationships / lookups are needed)

This version is intentionally fragile, by being recursive instead of iterative
(it's also not parallel, as a result)
This is to make sure that DHT black holes are visible if they exist
(the iterative parallel approach tends to get around them sometimes)
I haven't seen this get stuck on blackholes, but I also haven't proven it can't
Slight changes *do* make it blackhole hard, bootstrapping isn't an easy problem

*/

import (
	"container/heap"
	"time"
)

// Number of DHT buckets, equal to the number of bits in a NodeID.
// Note that, in practice, nearly all of these will be empty.
const dht_bucket_number = 8 * NodeIDLen

// Number of nodes to keep in each DHT bucket.
// Additional entries may be kept for peers, for bootstrapping reasons, if they don't already have an entry in the bucket.
const dht_bucket_size = 2

// Number of responses to include in a lookup.
// If extras are given, they will be truncated from the response handler to prevent abuse.
const dht_lookup_size = 16

// dhtInfo represents everything we know about a node in the DHT.
// This includes its key, a cache of it's NodeID, coords, and timing/ping related info for deciding who/when to ping nodes for maintenance.
type dhtInfo struct {
	nodeID_hidden *NodeID
	key           boxPubKey
	coords        []byte
	send          time.Time     // When we last sent a message
	recv          time.Time     // When we last received a message
	pings         int           // Decide when to drop
	throttle      time.Duration // Time to wait before pinging a node to bootstrap buckets, increases exponentially from 1 second to 1 minute
	bootstrapSend time.Time     // The time checked/updated as part of throttle checks
}

// Returns the *NodeID associated with dhtInfo.key, calculating it on the fly the first time or from a cache all subsequent times.
func (info *dhtInfo) getNodeID() *NodeID {
	if info.nodeID_hidden == nil {
		info.nodeID_hidden = getNodeID(&info.key)
	}
	return info.nodeID_hidden
}

// The nodes we known in a bucket (a region of keyspace with a matching prefix of some length).
type bucket struct {
	peers []*dhtInfo
	other []*dhtInfo
}

// Request for a node to do a lookup.
// Includes our key and coords so they can send a response back, and the destination NodeID we want to ask about.
type dhtReq struct {
	Key    boxPubKey // Key of whoever asked
	Coords []byte    // Coords of whoever asked
	Dest   NodeID    // NodeID they're asking about
}

// Response to a DHT lookup.
// Includes the key and coords of the node that's responding, and the destination they were asked about.
// The main part is Infos []*dhtInfo, the lookup response.
type dhtRes struct {
	Key    boxPubKey // key to respond to
	Coords []byte    // coords to respond to
	Dest   NodeID
	Infos  []*dhtInfo // response
}

// Information about a node, either taken from our table or from a lookup response.
// Used to schedule pings at a later time (they're throttled to 1/second for background maintenance traffic).
type dht_rumor struct {
	info   *dhtInfo
	target *NodeID
}

// The main DHT struct.
// Includes a slice of buckets, to organize known nodes based on their region of keyspace.
// Also includes information about outstanding DHT requests and the rumor mill of nodes to ping at some point.
type dht struct {
	core           *Core
	nodeID         NodeID
	buckets_hidden [dht_bucket_number]bucket // Extra is for the self-bucket
	peers          chan *dhtInfo             // other goroutines put incoming dht updates here
	reqs           map[boxPubKey]map[NodeID]time.Time
	offset         int
	rumorMill      []dht_rumor
}

// Initializes the DHT.
func (t *dht) init(c *Core) {
	t.core = c
	t.nodeID = *t.core.GetNodeID()
	t.peers = make(chan *dhtInfo, 1024)
	t.reqs = make(map[boxPubKey]map[NodeID]time.Time)
}

// Reads a request, performs a lookup, and responds.
// If the node that sent the request isn't in our DHT, but should be, then we add them.
func (t *dht) handleReq(req *dhtReq) {
	// Send them what they asked for
	loc := t.core.switchTable.getLocator()
	coords := loc.getCoords()
	res := dhtRes{
		Key:    t.core.boxPub,
		Coords: coords,
		Dest:   req.Dest,
		Infos:  t.lookup(&req.Dest, false),
	}
	t.sendRes(&res, req)
	// Also (possibly) add them to our DHT
	info := dhtInfo{
		key:    req.Key,
		coords: req.Coords,
	}
	// For bootstrapping to work, we need to add these nodes to the table
	// Using insertIfNew, they can lie about coords, but searches will route around them
	// Using the mill would mean trying to block off the mill becomes an attack vector
	t.insertIfNew(&info, false)
}

// Reads a lookup response, checks that we had sent a matching request, and processes the response info.
// This mainly consists of updating the node we asked in our DHT (they responded, so we know they're still alive), and adding the response info to the rumor mill.
func (t *dht) handleRes(res *dhtRes) {
	t.core.searches.handleDHTRes(res)
	reqs, isIn := t.reqs[res.Key]
	if !isIn {
		return
	}
	_, isIn = reqs[res.Dest]
	if !isIn {
		return
	}
	delete(reqs, res.Dest)
	now := time.Now()
	rinfo := dhtInfo{
		key:           res.Key,
		coords:        res.Coords,
		send:          now, // Technically wrong but should be OK...
		recv:          now,
		throttle:      time.Second,
		bootstrapSend: now,
	}
	// If they're already in the table, then keep the correct send time
	bidx, isOK := t.getBucketIndex(rinfo.getNodeID())
	if !isOK {
		return
	}
	b := t.getBucket(bidx)
	for _, oldinfo := range b.peers {
		if oldinfo.key == rinfo.key {
			rinfo.send = oldinfo.send
			rinfo.throttle = oldinfo.throttle
			rinfo.bootstrapSend = oldinfo.bootstrapSend
		}
	}
	for _, oldinfo := range b.other {
		if oldinfo.key == rinfo.key {
			rinfo.send = oldinfo.send
			rinfo.throttle = oldinfo.throttle
			rinfo.bootstrapSend = oldinfo.bootstrapSend
		}
	}
	// Insert into table
	t.insert(&rinfo, false)
	if res.Dest == *rinfo.getNodeID() {
		return
	} // No infinite recursions
	if len(res.Infos) > dht_lookup_size {
		// Ignore any "extra" lookup results
		res.Infos = res.Infos[:dht_lookup_size]
	}
	for _, info := range res.Infos {
		if dht_firstCloserThanThird(info.getNodeID(), &res.Dest, rinfo.getNodeID()) {
			t.addToMill(info, info.getNodeID())
		}
	}
}

// Heap structure used in lookups
type lheap struct {
	nodeID *NodeID    // NodeID of destination
	slice  []*dhtInfo // Underlying slice storage
}

func (h lheap) Len() int { return len(h.slice) }
func (h lheap) Less(i, j int) bool {
	return dht_firstCloserThanThird(h.slice[i].getNodeID(), h.nodeID, h.slice[j].getNodeID())
}
func (h lheap) Swap(i, j int)       { h.slice[i], h.slice[j] = h.slice[j], h.slice[i] }
func (h *lheap) Push(x interface{}) { h.slice = append(h.slice, x.(*dhtInfo)) }
func (h *lheap) Pop() interface{} {
	var ret interface{}
	ret, h.slice = h.slice[h.Len()-1], h.slice[:h.Len()-1]
	return ret
}

// Does a DHT lookup and returns the results, sorted in ascending order of distance from the destination.
func (t *dht) lookup(nodeID *NodeID, allowCloser bool) []*dhtInfo {
	h := lheap{nodeID: nodeID}
	addInfos := func(h heap.Interface, infos []*dhtInfo) {
		for _, info := range infos {
			if info == nil {
				panic("Should never happen!")
			}
			if allowCloser || dht_firstCloserThanThird(info.getNodeID(), nodeID, &t.nodeID) {
				heap.Push(h, info)
			}
		}
	}
	for bidx := 0; bidx < t.nBuckets(); bidx++ {
		b := t.getBucket(bidx)
		addInfos(&h, b.peers)
		addInfos(&h, b.other)
	}
	var res []*dhtInfo
	for len(res) < dht_lookup_size && h.Len() > 0 {
		res = append(res, heap.Pop(&h).(*dhtInfo))
	}
	return res
}

// Gets the bucket for a specified matching prefix length.
func (t *dht) getBucket(bidx int) *bucket {
	return &t.buckets_hidden[bidx]
}

// Lists the number of buckets.
func (t *dht) nBuckets() int {
	return len(t.buckets_hidden)
}

// Inserts a node into the DHT if they meet certain requirements.
// In particular, they must either be a peer that's not already in the DHT, or else be someone we should insert into the DHT (see: shouldInsert).
func (t *dht) insertIfNew(info *dhtInfo, isPeer bool) {
	// Insert if no "other" entry already exists
	nodeID := info.getNodeID()
	bidx, isOK := t.getBucketIndex(nodeID)
	if !isOK {
		return
	}
	b := t.getBucket(bidx)
	if (isPeer && !b.containsOther(info)) || t.shouldInsert(info) {
		// We've never heard this node before
		// TODO is there a better time than "now" to set send/recv to?
		// (Is there another "natural" choice that bootstraps faster?)
		info.send = time.Now()
		info.recv = info.send
		t.insert(info, isPeer)
	}
}

// Adds a node to the DHT, possibly removing another node in the process.
func (t *dht) insert(info *dhtInfo, isPeer bool) {
	// First update the time on this info
	info.recv = time.Now()
	// Get the bucket for this node
	nodeID := info.getNodeID()
	bidx, isOK := t.getBucketIndex(nodeID)
	if !isOK {
		return
	}
	b := t.getBucket(bidx)
	if !isPeer && !b.containsOther(info) {
		// This is a new entry, give it an old age so it's pinged sooner
		// This speeds up bootstrapping
		info.recv = info.recv.Add(-time.Hour)
	}
	if isPeer || info.throttle > time.Minute {
		info.throttle = time.Minute
	}
	// First drop any existing entry from the bucket
	b.drop(&info.key)
	// Now add to the *end* of the bucket
	if isPeer {
		// TODO make sure we don't duplicate peers in b.other too
		b.peers = append(b.peers, info)
		return
	}
	b.other = append(b.other, info)
	// Shrink from the *front* to requied size
	for len(b.other) > dht_bucket_size {
		b.other = b.other[1:]
	}
}

// Gets the bucket index for the bucket where we would put the given NodeID.
func (t *dht) getBucketIndex(nodeID *NodeID) (int, bool) {
	for bidx := 0; bidx < t.nBuckets(); bidx++ {
		them := nodeID[bidx/8] & (0x80 >> byte(bidx%8))
		me := t.nodeID[bidx/8] & (0x80 >> byte(bidx%8))
		if them != me {
			return bidx, true
		}
	}
	return t.nBuckets(), false
}

// Helper called by containsPeer, containsOther, and contains.
// Returns true if a node with the same ID *and coords* is already in the given part of the bucket.
func dht_bucket_check(newInfo *dhtInfo, infos []*dhtInfo) bool {
	// Compares if key and coords match
	if newInfo == nil {
		panic("Should never happen")
	}
	for _, info := range infos {
		if info == nil {
			panic("Should never happen")
		}
		if info.key != newInfo.key {
			continue
		}
		if len(info.coords) != len(newInfo.coords) {
			continue
		}
		match := true
		for idx := 0; idx < len(info.coords); idx++ {
			if info.coords[idx] != newInfo.coords[idx] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Calls bucket_check over the bucket's peers infos.
func (b *bucket) containsPeer(info *dhtInfo) bool {
	return dht_bucket_check(info, b.peers)
}

// Calls bucket_check over the bucket's other info.
func (b *bucket) containsOther(info *dhtInfo) bool {
	return dht_bucket_check(info, b.other)
}

// returns containsPeer || containsOther
func (b *bucket) contains(info *dhtInfo) bool {
	return b.containsPeer(info) || b.containsOther(info)
}

// Removes a node with the corresponding key, if any, from a bucket.
func (b *bucket) drop(key *boxPubKey) {
	clean := func(infos []*dhtInfo) []*dhtInfo {
		cleaned := infos[:0]
		for _, info := range infos {
			if info.key == *key {
				continue
			}
			cleaned = append(cleaned, info)
		}
		return cleaned
	}
	b.peers = clean(b.peers)
	b.other = clean(b.other)
}

// Sends a lookup request to the specified node.
func (t *dht) sendReq(req *dhtReq, dest *dhtInfo) {
	// Send a dhtReq to the node in dhtInfo
	bs := req.encode()
	shared := t.core.sessions.getSharedKey(&t.core.boxPriv, &dest.key)
	payload, nonce := boxSeal(shared, bs, nil)
	p := wire_protoTrafficPacket{
		Coords:  dest.coords,
		ToKey:   dest.key,
		FromKey: t.core.boxPub,
		Nonce:   *nonce,
		Payload: payload,
	}
	packet := p.encode()
	t.core.router.out(packet)
	reqsToDest, isIn := t.reqs[dest.key]
	if !isIn {
		t.reqs[dest.key] = make(map[NodeID]time.Time)
		reqsToDest, isIn = t.reqs[dest.key]
		if !isIn {
			panic("This should never happen")
		}
	}
	reqsToDest[req.Dest] = time.Now()
}

// Sends a lookup response to the specified node.
func (t *dht) sendRes(res *dhtRes, req *dhtReq) {
	// Send a reply for a dhtReq
	bs := res.encode()
	shared := t.core.sessions.getSharedKey(&t.core.boxPriv, &req.Key)
	payload, nonce := boxSeal(shared, bs, nil)
	p := wire_protoTrafficPacket{
		Coords:  req.Coords,
		ToKey:   req.Key,
		FromKey: t.core.boxPub,
		Nonce:   *nonce,
		Payload: payload,
	}
	packet := p.encode()
	t.core.router.out(packet)
}

// Returns true of a bucket contains no peers and no other nodes.
func (b *bucket) isEmpty() bool {
	return len(b.peers)+len(b.other) == 0
}

// Gets the next node that should be pinged from the bucket.
// There's a cooldown of 6 seconds between ping attempts for each node, to give them time to respond.
// It returns the least recently pinged node, subject to that send cooldown.
func (b *bucket) nextToPing() *dhtInfo {
	// Check the nodes in the bucket
	// Return whichever one responded least recently
	// Delay of 6 seconds between pinging the same node
	//  Gives them time to respond
	//  And time between traffic loss from short term congestion in the network
	var toPing *dhtInfo
	update := func(infos []*dhtInfo) {
		for _, next := range infos {
			if time.Since(next.send) < 6*time.Second {
				continue
			}
			if toPing == nil || next.recv.Before(toPing.recv) {
				toPing = next
			}
		}
	}
	update(b.peers)
	update(b.other)
	return toPing
}

// Returns a useful target address to ask about for pings.
// Equal to the our node's ID, except for exactly 1 bit at the bucket index.
func (t *dht) getTarget(bidx int) *NodeID {
	targetID := t.nodeID
	targetID[bidx/8] ^= 0x80 >> byte(bidx%8)
	return &targetID
}

// Sends a ping to a node, or removes the node if it has failed to respond to too many pings.
// If target is nil, we will ask the node about our own NodeID.
func (t *dht) ping(info *dhtInfo, target *NodeID) {
	if info.pings > 2 {
		bidx, isOK := t.getBucketIndex(info.getNodeID())
		if !isOK {
			panic("This should never happen")
		}
		b := t.getBucket(bidx)
		b.drop(&info.key)
		return
	}
	if target == nil {
		target = &t.nodeID
	}
	loc := t.core.switchTable.getLocator()
	coords := loc.getCoords()
	req := dhtReq{
		Key:    t.core.boxPub,
		Coords: coords,
		Dest:   *target,
	}
	info.pings++
	info.send = time.Now()
	t.sendReq(&req, info)
}

// Adds a node info and target to the rumor mill.
// The node will be asked about the target at a later point, if doing so would still be useful at the time.
func (t *dht) addToMill(info *dhtInfo, target *NodeID) {
	rumor := dht_rumor{
		info:   info,
		target: target,
	}
	t.rumorMill = append(t.rumorMill, rumor)
}

// Regular periodic maintenance.
// If the mill is empty, it adds two pings to the rumor mill.
// The first is to the node that responded least recently, provided that it's been at least 1 minute, to make sure we eventually detect and remove unresponsive nodes.
// The second is used for bootstrapping, and attempts to fill some bucket, iterating over buckets and resetting after it hits the last non-empty one.
// If the mill is not empty, it pops nodes from the mill until it finds one that would be useful to ping (see: shouldInsert), and then pings it.
func (t *dht) doMaintenance() {
	// First clean up reqs
	for key, reqs := range t.reqs {
		for target, timeout := range reqs {
			if time.Since(timeout) > time.Minute {
				delete(reqs, target)
			}
		}
		if len(reqs) == 0 {
			delete(t.reqs, key)
		}
	}
	if len(t.rumorMill) == 0 {
		// Ping the least recently contacted node
		//  This is to make sure we eventually notice when someone times out
		var oldest *dhtInfo
		last := 0
		for bidx := 0; bidx < t.nBuckets(); bidx++ {
			b := t.getBucket(bidx)
			if !b.isEmpty() {
				last = bidx
				toPing := b.nextToPing()
				if toPing == nil {
					continue
				} // We've recently pinged everyone in b
				if oldest == nil || toPing.recv.Before(oldest.recv) {
					oldest = toPing
				}
			}
		}
		if oldest != nil && time.Since(oldest.recv) > time.Minute {
			// Ping the oldest node in the DHT, but don't ping nodes that have been checked within the last minute
			t.addToMill(oldest, nil)
		}
		// Refresh buckets
		if t.offset > last {
			t.offset = 0
		}
		target := t.getTarget(t.offset)
		func() {
			closer := t.lookup(target, false)
			for _, info := range closer {
				// Throttled ping of a node that's closer to the destination
				if time.Since(info.recv) > info.throttle {
					t.addToMill(info, target)
					t.offset++
					info.bootstrapSend = time.Now()
					info.throttle *= 2
					if info.throttle > time.Minute {
						info.throttle = time.Minute
					}
					return
				}
			}
			if len(closer) == 0 {
				// If we don't know of anyone closer at all, then there's a hole in our dht
				// Ping the closest node we know and ignore the throttle, to try to fill it
				for _, info := range t.lookup(target, true) {
					t.addToMill(info, target)
					t.offset++
					return
				}
			}
		}()
		//t.offset++
	}
	for len(t.rumorMill) > 0 {
		var rumor dht_rumor
		rumor, t.rumorMill = t.rumorMill[0], t.rumorMill[1:]
		if rumor.target == rumor.info.getNodeID() {
			// Note that the above is a pointer comparison, and target can be nil
			// This is only for adding new nodes (learned from other lookups)
			// It only makes sense to ping if the node isn't already in the table
			if !t.shouldInsert(rumor.info) {
				continue
			}
		}
		t.ping(rumor.info, rumor.target)
		break
	}
}

// Returns true if it would be worth pinging the specified node.
// This requires that the bucket doesn't already contain the node, and that either the bucket isn't full yet or the node is closer to us in keyspace than some other node in that bucket.
func (t *dht) shouldInsert(info *dhtInfo) bool {
	bidx, isOK := t.getBucketIndex(info.getNodeID())
	if !isOK {
		return false
	}
	b := t.getBucket(bidx)
	if b.containsOther(info) {
		return false
	}
	if len(b.other) < dht_bucket_size {
		return true
	}
	for _, other := range b.other {
		if dht_firstCloserThanThird(info.getNodeID(), &t.nodeID, other.getNodeID()) {
			return true
		}
	}
	return false
}

// Returns true if the keyspace distance between the first and second node is smaller than the keyspace distance between the second and third node.
func dht_firstCloserThanThird(first *NodeID,
	second *NodeID,
	third *NodeID) bool {
	for idx := 0; idx < NodeIDLen; idx++ {
		f := first[idx] ^ second[idx]
		t := third[idx] ^ second[idx]
		if f == t {
			continue
		}
		return f < t
	}
	return false
}

// Resets the DHT in response to coord changes.
// This empties all buckets, resets the bootstrapping cycle to 0, and empties the rumor mill.
// It adds all old "other" node info to the rumor mill, so they'll be pinged quickly.
// If those nodes haven't also changed coords, then this is a relatively quick way to notify those nodes of our new coords and re-add them to our own DHT if they respond.
func (t *dht) reset() {
	// This is mostly so bootstrapping will reset to resend coords into the network
	t.offset = 0
	t.rumorMill = nil // reset mill
	for _, b := range t.buckets_hidden {
		b.peers = b.peers[:0]
		for _, info := range b.other {
			// Add other nodes to the rumor mill so they'll be pinged soon
			// This will hopefully tell them our coords and re-learn theirs quickly if they haven't changed
			t.addToMill(info, info.getNodeID())
		}
		b.other = b.other[:0]
	}
}
