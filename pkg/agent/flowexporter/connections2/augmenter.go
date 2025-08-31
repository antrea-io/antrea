package connections2

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"time"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
)

type Augmenter interface {
	GetMeta(ctx context.Context, key connection.ConnKey) (*connection.ConnMeta, error)
}

// ExampleAugmenter simulates an expensive fetch for metadata and caches results.
type ExampleAugmenter struct {
	cache map[connection.ConnKey]*connection.ConnMeta
}

func NewExampleAugmenter() *ExampleAugmenter {
	return &ExampleAugmenter{
		cache: make(map[connection.ConnKey]*connection.ConnMeta),
	}
}

func (a *ExampleAugmenter) GetMeta(ctx context.Context, key connection.ConnKey) (*connection.ConnMeta, error) {
	// fast path: cached
	if m, ok := a.cache[key]; ok {
		return m, nil
	}
	// simulate expensive metadata retrieval (e.g., k8s API)
	// in production this would be async/cached with watchers; keep it simple here
	time.Sleep(50 * time.Millisecond) // expensive op
	m := &connection.ConnMeta{
		ID:                         rand.Uint32(),
		SourcePodNamespace:         fmt.Sprintf("ns-%d", rand.Intn(10)),
		SourcePodName:              fmt.Sprintf("pod-%d", rand.Intn(200)),
		DestinationPodNamespace:    "default",
		DestinationPodName:         fmt.Sprintf("svc-%d", rand.Intn(20)),
		DestinationServicePortName: "http",
		OriginalDestinationAddress: netip.AddrFrom4([4]byte{10, byte(rand.Intn(255)), 0, 1}),
		OriginalDestinationPort:    80,
		Labels:                     []byte("example"),
	}
	a.cache[key] = m
	return m, nil
}
