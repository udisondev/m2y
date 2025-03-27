package node

import "sync"

type messageCache struct {
	pos   int
	mu    sync.RWMutex
	bucks []cacheBucket
}

type cacheBucket struct {
	count int
	m     map[string]struct{}
}

func newMessageCache() messageCache {
	bucketes := make([]cacheBucket, bucketsCount)

	for i := range bucketes {
		bucketes[i] = cacheBucket{
			count: bucketCapacity,
			m:     make(map[string]struct{}, bucketCapacity),
		}
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

	b = cacheBucket{m: make(map[string]struct{}, bucketCapacity)}
	mc.bucks[mc.pos] = b

	b.put(nonce)
}

func (mc *messageCache) putIfAbsent(nonce string) bool {
	mc.mu.RLock()
	for i := len(mc.bucks) - 1; i >= 0; i-- {
		if mc.bucks[i].exists(nonce) {
			return true
		}
	}
	mc.mu.RUnlock()

	mc.put(nonce)
	return false
}

func (cb *cacheBucket) put(nonce string) bool {
	if cb.count > bucketCapacity/100*8 {
		return false
	}
	cb.m[nonce] = struct{}{}
	cb.count++
	return true
}

func (cb *cacheBucket) exists(nonce string) bool {
	_, ok := cb.m[nonce]

	return ok
}
