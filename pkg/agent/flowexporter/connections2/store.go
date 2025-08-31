package connections2

import (
	"container/heap"
	"context"
	"sync/atomic"
	"time"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
)

type updateMsg struct {
	key     connection.ConnKey
	version uint32
	lastMs  int64
	deleted bool
}

type subscriber struct {
	ch    chan updateMsg
	dirty atomic.Uint32
}

type snapshot struct {
	ents map[connection.ConnKey]connection.ConnEntry // shallow copy of hot entries (values, not pointers)
}

type Store struct {
	updCh    chan []connection.ConnEntry // writers submit augmented entries (hot+meta pointer)
	addSubCh chan *subscriber
	delSubCh chan *subscriber
	stopCh   chan struct{}

	staleConnectionTimeout time.Duration

	ents  map[connection.ConnKey]*connection.ConnEntry // single-writer-owned map
	gc    gcHeap
	ttlMs int64

	subs map[*subscriber]struct{}

	// snapshot for readers (RCU-like)
	snap atomic.Pointer[snapshot]
}

func NewStore(ctx context.Context, ttl time.Duration) *Store {
	s := &Store{
		updCh:                  make(chan []connection.ConnEntry, 16),
		addSubCh:               make(chan *subscriber, 8),
		delSubCh:               make(chan *subscriber, 8),
		stopCh:                 make(chan struct{}),
		ents:                   make(map[connection.ConnKey]*connection.ConnEntry, 4096),
		ttlMs:                  ttl.Milliseconds(),
		staleConnectionTimeout: ttl,
		subs:                   make(map[*subscriber]struct{}),
	}
	ss := &snapshot{ents: make(map[connection.ConnKey]connection.ConnEntry, 4096)}
	s.snap.Store(ss)
	go s.run(ctx)
	return s
}

func (s *Store) run(ctx context.Context) {
	gcTicker := time.NewTicker(2 * time.Second)
	defer gcTicker.Stop()
	for {
		select {
		case batch := <-s.updCh:
			now := nowMs()
			ss := s.snap.Load()
			cow := false
			for i := range batch {
				in := batch[i]
				e, ok := s.ents[in.Key]
				if !ok {
					// new entry: allocate and take meta pointer
					copyEntry := in // make local copy
					e = &copyEntry
					s.ents[in.Key] = e
				} else {
					// update hot fields in-place (single-writer)
					e.OriginalPackets = in.OriginalPackets
					e.OriginalBytes = in.OriginalBytes
					e.ReversePackets = in.ReversePackets
					e.ReverseBytes = in.ReverseBytes
					e.IsActive = in.IsActive
					e.IsPresent = in.IsPresent
					e.ReadyToDelete = in.ReadyToDelete
					e.Zone = in.Zone
					e.Mark = in.Mark
					e.StatusFlag = in.StatusFlag
					// update meta pointer only if provided and different
					if in.Meta != nil && e.Meta != in.Meta {
						e.Meta = in.Meta
					}
				}
				// update time + version for every submission (we decide version bumping rules)
				e.LastUpdateMs = now
				e.Version++

				// push GC marker
				exp := now + s.ttlMs
				heap.Push(&s.gc, &gcItem{key: in.Key, expiryMs: exp})

				// publish update to subscribers (non-blocking)
				u := updateMsg{key: in.Key, version: e.Version, lastMs: e.LastUpdateMs, deleted: false}
				for sub := range s.subs {
					select {
					case sub.ch <- u:
					default:
						sub.dirty.Store(1)
					}
				}

				// snapshot COW for touched keys only
				if !cow {
					newm := make(map[connection.ConnKey]connection.ConnEntry, len(ss.ents)+len(batch))
					for k, v := range ss.ents {
						newm[k] = v
					}
					ss = &snapshot{ents: newm}
					cow = true
				}
				// store a shallow copy in snapshot
				ss.ents[in.Key] = connection.ConnEntry{
					Key:             in.Key,
					Meta:            e.Meta,
					LastUpdateMs:    e.LastUpdateMs,
					Version:         e.Version,
					OriginalPackets: e.OriginalPackets,
					OriginalBytes:   e.OriginalBytes,
					ReversePackets:  e.ReversePackets,
					ReverseBytes:    e.ReverseBytes,
					IsActive:        e.IsActive,
					IsPresent:       e.IsPresent,
					ReadyToDelete:   e.ReadyToDelete,
					Zone:            e.Zone,
					Mark:            e.Mark,
					StatusFlag:      e.StatusFlag,
				}
			}
			if cow {
				s.snap.Store(ss)
			}

		case <-gcTicker.C:
			now := nowMs()
			for len(s.gc) > 0 {
				top := s.gc[0]
				if top.expiryMs > now {
					break
				}
				heap.Pop(&s.gc)
				e := s.ents[top.key]
				if e == nil {
					continue
				}
				if e.LastUpdateMs+s.ttlMs <= now {
					// delete entry
					delete(s.ents, top.key)
					// update snapshot if present
					ss := s.snap.Load()
					if _, ok := ss.ents[top.key]; ok {
						newm := make(map[connection.ConnKey]connection.ConnEntry, len(ss.ents))
						for k, v := range ss.ents {
							newm[k] = v
						}
						delete(newm, top.key)
						s.snap.Store(&snapshot{ents: newm})
					}
					// publish deletion
					u := updateMsg{key: top.key, deleted: true}
					for sub := range s.subs {
						select {
						case sub.ch <- u:
						default:
							sub.dirty.Store(1)
						}
					}
				}
			}

		case sub := <-s.addSubCh:
			s.subs[sub] = struct{}{}
			sub.dirty.Store(1) // force initial resync

		case sub := <-s.delSubCh:
			delete(s.subs, sub)

		case <-s.stopCh:
			return

		case <-ctx.Done():
			return
		}
	}
}

func nowMs() int64 { return time.Now().UnixNano() / int64(time.Millisecond) }

// SubmitAugmentedBatch: the poller + augmenter should call this with ConnEntry that have Meta set
func (s *Store) SubmitAugmentedBatch(batch []connection.ConnEntry) {
	if len(batch) == 0 {
		return
	}
	select {
	case s.updCh <- batch:
	default:
		// if buffer full, do a blocking send (prefer correctness). Alternatively, drop if desired.
		s.updCh <- batch
	}
}

func (s *Store) RegisterConsumer() *subscriber {
	sub := &subscriber{ch: make(chan updateMsg, 1024)}
	select {
	case s.addSubCh <- sub:
	default:
		s.addSubCh <- sub
	}
	return sub
}

func (s *Store) UnregisterConsumer(sub *subscriber) {
	select {
	case s.delSubCh <- sub:
	default:
		s.delSubCh <- sub
	}
}
