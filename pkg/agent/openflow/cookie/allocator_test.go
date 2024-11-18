// Copyright 2019 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cookie

import (
	"math/rand/v2" // Updated import path to use math/rand/v2
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	seed            = 1                   // Define a fixed seed for deterministic tests
	fakeClusterUUID = "fake-cluster-uuid" // Define a fake cluster UUID for testing
)

var result ID // Ensures that the call to Request is not optimized-out by the compiler.

// BenchmarkIDAllocate benchmarks the allocation of IDs.
func BenchmarkIDAllocate(b *testing.B) {
	a := NewAllocator(0)
	for i := 0; i < b.N; i++ {
		result = a.Request(Default)
	}
}

// TestConcurrentAllocate spawns multiple goroutines to ensure that the allocator is thread-safe.
func TestConcurrentAllocate(t *testing.T) {
	eachTotal := 10000
	concurrentNum := 8

	// #nosec G404: random number generator not used for security purposes
	mainRand := rand.New(rand.NewPCG(1, 0)) // Initialize with fixed seeds for deterministic behavior
	round := mainRand.Uint64() >> (64 - BitwidthRound)
	a := NewAllocator(round)

	eachGoroutine := func(randSrc *rand.Rand) {
		var seq []Category

		for i := 0; i < eachTotal; i++ {
			seq = append(seq, NetworkPolicy, Service, PodConnectivity, Default)
		}
		randSrc.Shuffle(len(seq), func(aIdx, bIdx int) { seq[aIdx], seq[bIdx] = seq[bIdx], seq[aIdx] })

		for i := 0; i < eachTotal/2; i++ {
			id := a.Request(seq[i])
			assert.Equal(t, round, id.Round(), id.String())
			assert.Equal(t, seq[i].String(), id.Category().String(), id.String())
		}

		for i := 0; i < eachTotal; i++ {
			id := a.Request(seq[i])
			assert.Equal(t, round, id.Round(), id.String())
			assert.Equal(t, seq[i].String(), id.Category().String(), id.String())
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < concurrentNum; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each goroutine gets its own rand.Rand instance with unique seeds for independent shuffles
			goroutineRandSrc := rand.New(rand.NewPCG(mainRand.Uint64(), mainRand.Uint64()))
			eachGoroutine(goroutineRandSrc)
		}()
	}
	wg.Wait()
}
