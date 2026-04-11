package reassembly

import (
	"fmt"
	"sync"
	"time"
)

type Assembler struct {
	mu      sync.Mutex
	timeout time.Duration
	parts   map[uint64]*partial
}

type partial struct {
	updatedAt time.Time
	pieces    map[int][]byte
	lastIndex int
}

func New(timeout time.Duration) *Assembler {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Assembler{
		timeout: timeout,
		parts:   make(map[uint64]*partial),
	}
}

func (a *Assembler) Add(offset uint64, fragmentIndex int, last bool, data []byte) ([]byte, bool, error) {
	if fragmentIndex < 0 || fragmentIndex > 63 {
		return nil, false, fmt.Errorf("fragment index %d out of range", fragmentIndex)
	}

	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()

	a.pruneLocked(now)

	current := a.parts[offset]
	if current == nil {
		current = &partial{
			updatedAt: now,
			pieces:    make(map[int][]byte, 4),
			lastIndex: -1,
		}
		a.parts[offset] = current
	}
	current.updatedAt = now

	if _, exists := current.pieces[fragmentIndex]; exists {
		return nil, false, nil
	}
	current.pieces[fragmentIndex] = append([]byte(nil), data...)
	if last {
		if current.lastIndex >= 0 && current.lastIndex != fragmentIndex {
			delete(a.parts, offset)
			return nil, false, fmt.Errorf("conflicting last fragment markers for offset %d", offset)
		}
		current.lastIndex = fragmentIndex
	}
	if current.lastIndex < 0 {
		return nil, false, nil
	}
	if len(current.pieces) != current.lastIndex+1 {
		return nil, false, nil
	}

	total := 0
	for i := 0; i <= current.lastIndex; i++ {
		piece, ok := current.pieces[i]
		if !ok {
			return nil, false, nil
		}
		total += len(piece)
	}

	out := make([]byte, 0, total)
	for i := 0; i <= current.lastIndex; i++ {
		out = append(out, current.pieces[i]...)
	}
	delete(a.parts, offset)
	return out, true, nil
}

func (a *Assembler) Prune(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(now)
}

func (a *Assembler) pruneLocked(now time.Time) {
	for offset, current := range a.parts {
		if now.Sub(current.updatedAt) > a.timeout {
			delete(a.parts, offset)
		}
	}
}
