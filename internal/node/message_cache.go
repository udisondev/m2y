package node

import "sync"

type messageCache struct {
	pos   int
	mu    sync.RWMutex
	bucks []bucket
}

type bucket map[string]struct{}

func newMessageCache() messageCache {
	bucketes := make([]bucket, bucketsCount)

	for i := range bucketes {
		bucketes[i] = make(map[string]struct{}, bucketCapacity)
	}

	return messageCache{
		bucks: bucketes,
	}
}

func (mc *messageCache) put(nonce string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	b := mc.bucks[mc.pos]

	ok := b.put(nonce)
	if ok {
		return
	}

	mc.pos++
	if mc.pos > len(mc.bucks) {
		mc.pos = 0
	}

	b = make(map[string]struct{}, bucketCapacity)
	mc.bucks[mc.pos] = b

	b.put(nonce)
}

func (mc *messageCache) putIfAbsent(nonce string) bool {
	mc.mu.RLock()
	for i := len(mc.bucks) - 1; i >= 0; i-- {
		if _, ok := mc.bucks[i][nonce]; ok {
			return true
		}
	}
	mc.mu.RUnlock()

	mc.put(nonce)
	return false
}

func (b bucket) put(nonce string) bool {
	if len(b) > bucketCapacity/100*8 {
		return false
	}
	b[nonce] = struct{}{}
	return true
}
