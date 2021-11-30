// Copyright 2021 Antrea Authors
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

package utils

import (
	"crypto/rand"
	"math"
	"math/big"
	rand1 "math/rand"
	"time"

	"k8s.io/client-go/util/retry"
)

const PodOnRealNodeLabelKey = "realNode"

// LabelCandidates ...
// label number:              1   2   3   4   5   6   7   8   9   10  11 12
// pods cover percents:       80% 64% 51% 41% 32% 25% 20% 16% 13% 10% 8% 6%
var LabelCandidates = []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"}

func DefaultRetry(fn func() error) error {
	return retry.OnError(retry.DefaultRetry, func(_ error) bool { return true }, fn)
}

func GenRandInt() int64 {
	b := new(big.Int).SetInt64(int64(math.MaxInt64))
	i, err := rand.Int(rand.Reader, b)
	if err != nil {
		return 0
	}
	return i.Int64()
}

// PickLabels random select specific number of labels, if realNode is true, then no simulate node
// will be selected. By selecting different number of labels, we can control the size of the
// portion of the Pods we selected.
func PickLabels(num int, realNode bool) map[string]string {
	rand1.Shuffle(len(LabelCandidates), func(i, j int) {
		LabelCandidates[i], LabelCandidates[j] = LabelCandidates[j], LabelCandidates[i]
	})
	result := make(map[string]string)
	for i := 0; i < num; i++ {
		result[LabelCandidates[i]] = ""
	}
	if len(result) == 0 { // re-pick if no labels is picked.
		return PickLabels(num, realNode)
	}
	if realNode {
		result[PodOnRealNodeLabelKey] = ""
	}
	return result
}

func CheckTimeout(start time.Time, duration time.Duration) bool {
	if time.Since(start) > duration {
		return true
	}
	return false
}
