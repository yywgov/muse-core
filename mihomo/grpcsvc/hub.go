package grpcsvc

import "sync"

// hub fans a value out to subscribers; a full subscriber misses values instead of blocking the
// publisher (status listeners resync on their own, log lines are best effort).
type hub[T any] struct {
	mu   sync.Mutex
	subs map[chan T]struct{}
}

func newHub[T any]() *hub[T] { return &hub[T]{subs: map[chan T]struct{}{}} }

func (h *hub[T]) subscribe(buf int) (<-chan T, func()) {
	ch := make(chan T, buf)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs, ch)
			h.mu.Unlock()
		})
	}
}

func (h *hub[T]) publish(v T) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- v:
		default:
		}
	}
}

func (h *hub[T]) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}
