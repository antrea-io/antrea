// Copyright 2020 Antrea Authors
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

package handlers

// HandlerError is for errors returned by the API handler funcs.
type HandlerError struct {
	error
	// The HTTP status code that will be returned to the API client.
	HTTPStatusCode int
}

func NewHandlerError(err error, statusCode int) *HandlerError {
	return &HandlerError{err, statusCode}
}
