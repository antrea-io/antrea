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

package antctl

import (
	"fmt"
	"net/http"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func generateMessage(cd *commandDefinition, args map[string]string, isResourceRequest bool, err error) error {
	if err == nil {
		// no error, nothing to do
		return nil
	}
	// The rest client's Do method can return the following error types:
	//   - If the server responds with a status: *errors.StatusError or *errors.UnexpectedObjectError
	//   - http.Client.Do errors are returned directly.
	// The rest client's DoRaw method can return errors of type *errors.StatusError.
	if statusErr, ok := err.(*errors.StatusError); ok {
		return generateMessageForStatusErr(cd, args, isResourceRequest, statusErr)
	}
	return fmt.Errorf("unknown error: %w", err)
}

func generateMessageForStatusErr(cd *commandDefinition, args map[string]string, isResourceRequest bool, statusErr *errors.StatusError) error {
	if isResourceRequest {
		return fmt.Errorf("request to server failed: %s", statusErr.Error())
	}
	code := int(statusErr.ErrStatus.Code)
	if code == 0 {
		return fmt.Errorf("missing code in status error: %w", statusErr)
	}
	// This status cause will be populated for non-resource requests, i.e., requests performed
	// with the rest client's DoRaw method.
	// https://github.com/kubernetes/apimachinery/blob/4b14f804a0babdcc58e695d72f77ad29f536511e/pkg/api/errors/errors.go#L499-L506
	if cause, ok := errors.StatusCause(statusErr, metav1.CauseTypeUnexpectedServerResponse); ok && len(cause.Message) > 0 {
		return fmt.Errorf("request to server failed: %s: %s", http.StatusText(code), cause.Message)
	}
	return fmt.Errorf("request to server failed: %s: %s", http.StatusText(code), statusErr.Error())
}
