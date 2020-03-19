package yggdrasil

// This thing manages search packets

// The basic idea is as follows:
//  We may know a NodeID (with a mask) and want to connect
//  We begin a search by initializing a list of all nodes in our DHT, sorted by closest to the destination
//  We then iteratively ping nodes from the search, marking each pinged node as visited
//  We add any unvisited nodes from ping responses to the search, truncating to some maximum search size
//  This stops when we either run out of nodes to ping (we hit a dead end where we can't make progress without going back), or we reach the destination
//  A new search packet is sent immediately after receiving a response
//  A new search packet is sent periodically, once per second, in case a packet was dropped (this slowly causes the search to become parallel if the search doesn't timeout but also doesn't finish within 1 second for whatever reason)

// TODO?
//  Some kind of max search steps, in case the node is offline, so we don't crawl through too much of the network looking for a destination that isn't there?

import (
	"errors"
	"sort"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/crypto"
)

const search_TIMEOUT = 3 * time.Second
const search_RETRY_TIME = 100 * time.Millisecond
const search_MAX_RESULTS = dht_lookup_size
const search_MAX_RETRY = 3

type searchRumor struct {
	key    crypto.BoxPubKey
	coords string //string([]byte) of coords, usable as a map key
}

type searchVisiting struct {
	sr   searchRumor
	info *dhtInfo
}

// Information about an ongoing search.
// Includes the target NodeID, the bitmask to match it to an IP, and the list of nodes to visit / already visited.
type searchInfo struct {
	searches *searches
	dest     crypto.NodeID
	mask     crypto.NodeID
	timer    *time.Timer
	visited  map[crypto.BoxPubKey]struct{} // key+coord pairs visited so far
	visiting []*searchVisiting
	closest  []*crypto.NodeID
	callback func(*sessionInfo, error)
	// TODO context.Context for timeout and cancellation
	send uint64 // log number of requests sent
	recv uint64 // log number of responses received
}

// This stores a map of active searches.
type searches struct {
	router   *router
	searches map[crypto.NodeID]*searchInfo
}

// Initializes the searches struct.
func (s *searches) init(r *router) {
	s.router = r
	s.searches = make(map[crypto.NodeID]*searchInfo)
}

func (s *searches) reconfigure() {
	// This is where reconfiguration would go, if we had anything to do
}

// Creates a new search info, adds it to the searches struct, and returns a pointer to the info.
func (s *searches) createSearch(dest *crypto.NodeID, mask *crypto.NodeID, callback func(*sessionInfo, error)) *searchInfo {
	info := searchInfo{
		searches: s,
		dest:     *dest,
		mask:     *mask,
		callback: callback,
	}
	info.closest = append(info.closest, &info.dest)
	s.searches[*dest] = &info
	return &info
}

////////////////////////////////////////////////////////////////////////////////

// Checks if there's an ongoing search related to a dhtRes.
// If there is, it adds the response info to the search and triggers a new search step.
// If there's no ongoing search, or we if the dhtRes finished the search (it was from the target node), then don't do anything more.
func (sinfo *searchInfo) handleDHTRes(res *dhtRes) {
	if sinfo != sinfo.searches.searches[sinfo.dest] {
		// Search already over
		return
	}
	if res != nil {
		sinfo.recv++
		if _, isIn := sinfo.visited[res.Key]; !isIn {
			sinfo.visited[res.Key] = struct{}{}
			if sinfo.checkDHTRes(res) {
				return // Search finished successfully
			}
			// Use results to start an additional search thread
			infos := sinfo.getAllowedInfos(res)
			sinfo.addToSearch(infos)
		}
	}
}

func (sinfo *searchInfo) sendSearchLookup(sv *searchVisiting) {
	rq := dhtReqKey{sv.info.key, sinfo.dest}
	sinfo.searches.router.dht.addCallback(&rq, sinfo.handleDHTRes)
	sinfo.searches.router.dht.ping(sv.info, &sinfo.dest)
	sinfo.send++
	if sinfo.timer != nil {
		sinfo.timer.Stop()
	}
	sinfo.timer = time.AfterFunc(search_RETRY_TIME, func() {
		sinfo.searches.router.Act(nil, func() { sinfo.retryVisiting() })
	})
	sinfo.searches.router.core.log.Debugln("Sending search lookup:", &sinfo.dest, sv.info.getNodeID(), sinfo.send, sinfo.recv, len(sinfo.visiting))
}

func (sinfo *searchInfo) retryVisiting() {
	if sfo := sinfo.searches.searches[sinfo.dest]; sfo != sinfo {
		return // search already over
	}
	for {
		if len(sinfo.visiting) > 0 {
			svv := sinfo.visiting[0]
			sinfo.visiting = sinfo.visiting[1:]
			if _, isIn := sinfo.visited[svv.info.key]; isIn {
				continue
			}
			sinfo.sendSearchLookup(svv)
			break
		} else {
			if sinfo.timer != nil {
				sinfo.timer.Stop()
			}
			sinfo.timer = time.AfterFunc(search_TIMEOUT, func() {
				if sfo := sinfo.searches.searches[sinfo.dest]; sfo != sinfo {
					return // search already over
				}
				delete(sinfo.searches.searches, sinfo.dest)
				sinfo.callback(nil, errors.New("search timeout"))
				sinfo.searches.router.core.log.Debugln("Search timeout:", &sinfo.dest, sinfo.send, sinfo.recv)
			})
			break
		}
	}
}

// Get a list of search targets that are close enough to the destination to try
// Requires an initial list as input
func (sinfo *searchInfo) getAllowedInfos(res *dhtRes) []*dhtInfo {
	infos := append([]*dhtInfo(nil), res.Infos...)
	sort.SliceStable(infos, func(i, j int) bool {
		// Should return true if i is closer to the destination than j
		return dht_ordered(&sinfo.dest, infos[i].getNodeID(), infos[j].getNodeID())
	})
	// Remove anything further from the destination than the closest node visited so far
	from := dhtInfo{key: res.Key, coords: res.Coords}
	for idx, info := range infos {
		if from.key == info.key || !dht_ordered(&sinfo.dest, info.getNodeID(), sinfo.closest[len(sinfo.closest)-1]) {
			infos = infos[:idx]
			break
		}
	}
	// Make sure there's some kind of limit
	if len(infos) > search_MAX_RESULTS {
		infos = infos[:search_MAX_RESULTS]
	}
	return infos
}

func (sinfo *searchInfo) addToSearch(infos []*dhtInfo) {
	m := make(map[searchRumor]*searchVisiting)
	for _, sv := range sinfo.visiting {
		if _, isIn := sinfo.visited[sv.info.key]; isIn {
			continue
		}
		m[sv.sr] = sv
	}
	for _, info := range infos {
		sr := searchRumor{info.key, string(info.coords)}
		if _, isIn := sinfo.visited[info.key]; isIn {
			continue
		} else if _, isIn := m[sr]; isIn {
			continue
		}
		sv := &searchVisiting{sr, info}
		m[sr] = sv
		//sinfo.sendSearchLookup(svv)
	}
	sinfo.visiting = sinfo.visiting[:0]
	for _, svv := range m {
		sinfo.visiting = append(sinfo.visiting, svv)
	}
	sort.SliceStable(sinfo.visiting, func(i, j int) bool {
		// Should return true if i is closer to the destination than j
		return dht_ordered(&sinfo.dest, sinfo.visiting[i].info.getNodeID(), sinfo.visiting[j].info.getNodeID())
	})
	sinfo.retryVisiting()
}

// Initially start a search
func (sinfo *searchInfo) startSearch() {
	loc := sinfo.searches.router.core.switchTable.getLocator()
	var infos []*dhtInfo
	infos = append(infos, &dhtInfo{
		key:    sinfo.searches.router.core.boxPub,
		coords: loc.getCoords(),
	})
	// Start the search by asking ourself, useful if we're the destination
	sinfo.addToSearch(infos)
}

// Calls create search, and initializes the iterative search parts of the struct before returning it.
func (s *searches) newIterSearch(dest *crypto.NodeID, mask *crypto.NodeID, callback func(*sessionInfo, error)) *searchInfo {
	// TODO remove this function, just do it all in createSearch
	sinfo := s.createSearch(dest, mask, callback)
	sinfo.visited = make(map[crypto.BoxPubKey]struct{})
	return sinfo
}

// Checks if a dhtRes is good (called by handleDHTRes).
// If the response is from the target, get/create a session, trigger a session ping, and return true.
// Otherwise return false.
func (sinfo *searchInfo) checkDHTRes(res *dhtRes) bool {
	from := dhtInfo{key: res.Key, coords: res.Coords}
	them := from.getNodeID()
	sinfo.closest = append(sinfo.closest, them)
	sort.SliceStable(sinfo.closest, func(i, j int) bool {
		// Should return true if i is closer to the destination than j
		return dht_ordered(&sinfo.dest, sinfo.closest[i], sinfo.closest[j])
	})
	if len(sinfo.closest) > search_MAX_RESULTS {
		sinfo.closest = sinfo.closest[:search_MAX_RESULTS]
	}
	if dht_ordered(&sinfo.dest, them, sinfo.closest[len(sinfo.closest)-1]) {
		sinfo.searches.router.core.log.Debugln("Updating search:", &sinfo.dest, them, sinfo.send, sinfo.recv)
	}
	var destMasked crypto.NodeID
	var themMasked crypto.NodeID
	for idx := 0; idx < crypto.NodeIDLen; idx++ {
		destMasked[idx] = sinfo.dest[idx] & sinfo.mask[idx]
		themMasked[idx] = them[idx] & sinfo.mask[idx]
	}
	if themMasked != destMasked {
		return false
	}
	finishSearch := func(sess *sessionInfo, err error) {
		if sess != nil {
			// FIXME (!) replay attacks could mess with coords? Give it a handle (tstamp)?
			sess.Act(sinfo.searches.router, func() { sess.coords = res.Coords })
			sess.ping(sinfo.searches.router)
		}
		if err != nil {
			sinfo.callback(nil, err)
		} else {
			sinfo.callback(sess, nil)
		}
		// Cleanup
		if _, isIn := sinfo.searches.searches[sinfo.dest]; isIn {
			sinfo.searches.router.core.log.Debugln("Finished search:", &sinfo.dest, sinfo.send, sinfo.recv)
			delete(sinfo.searches.searches, sinfo.dest)
		}
	}
	// They match, so create a session and send a sessionRequest
	var err error
	sess, isIn := sinfo.searches.router.sessions.getByTheirPerm(&res.Key)
	if !isIn {
		// Don't already have a session
		sess = sinfo.searches.router.sessions.createSession(&res.Key)
		if sess == nil {
			err = errors.New("session not allowed")
		} else if _, isIn := sinfo.searches.router.sessions.getByTheirPerm(&res.Key); !isIn {
			panic("This should never happen")
		}
	} else {
		err = errors.New("session already exists")
	}
	finishSearch(sess, err)
	return true
}
