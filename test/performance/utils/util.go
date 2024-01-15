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
	"time"

	"k8s.io/client-go/util/retry"
)

const PodOnRealNodeLabelKey = "realNode"

const (
	SelectorLabelKeySuffix   = "app-"
	SelectorLabelValueSuffix = "scale-"
)

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

func CheckTimeout(start time.Time, duration time.Duration) bool {
	if time.Since(start) > duration {
		return true
	}
	return false
}
