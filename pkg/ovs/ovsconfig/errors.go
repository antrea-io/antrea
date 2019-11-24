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

package ovsconfig

import (
	"strings"
)

type Error interface {
	error
	Timeout() bool   // Is the error a timeout?
	Temporary() bool // Is the error temporary?
}

type TransactionError struct {
	error
	temporary bool
}

func NewTransactionError(err error, temporary bool) *TransactionError {
	return &TransactionError{err, temporary}
}

func (e *TransactionError) Temporary() bool {
	return e.temporary || e.Timeout()
}

func (e *TransactionError) Timeout() bool {
	return strings.HasPrefix(e.Error(), "timed out:")
}

type InvalidArgumentsError string

func newInvalidArgumentsError(err string) InvalidArgumentsError {
	return InvalidArgumentsError(err)
}

func (e InvalidArgumentsError) Error() string {
	return string(e)
}

func (e InvalidArgumentsError) Temporary() bool {
	return false
}

func (e InvalidArgumentsError) Timeout() bool {
	return false
}
