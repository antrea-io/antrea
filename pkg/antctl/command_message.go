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
	"k8s.io/client-go/rest"
)

func generateMessage(opt *requestOption, result rest.Result) error {
	var code int
	_ = result.StatusCode(&code)
	if errMsg := generate(opt.commandDefinition, opt.args, code, result.Error().Error()); errMsg != nil {
		return errMsg
	}
	return result.Error()
}

func generateMessageForStatusErr(cd *commandDefinition, args map[string]string, statusErr *errors.StatusError) error {
	if statusErr.ErrStatus.Details.Causes == nil || len(statusErr.ErrStatus.Details.Causes[0].Message) == 0 {
		return generate(cd, args, int(statusErr.ErrStatus.Code), statusErr.Error())
	}
	return fmt.Errorf("%s: %s", statusErr.ErrStatus.Reason, statusErr.ErrStatus.Details.Causes[0].Message)
}

func generate(cd *commandDefinition, args map[string]string, code int, err string) error {
	if len(err) > 0 {
		if len(http.StatusText(code)) == 0 {
			return fmt.Errorf("%s", err)
		}
		return fmt.Errorf("%s: %s", http.StatusText(code), err)
	}
	switch code {
	case http.StatusNotFound:
		return fmt.Errorf("NotFound: %s \"%s\" not found", cd.use, args["name"])
	case http.StatusInternalServerError:
		return fmt.Errorf("InternalServerError: Encoding response failed for %s", cd.use)
	case http.StatusBadRequest:
		return fmt.Errorf("BadRequest: Please check the args for %s", cd.use)
	default:
		return fmt.Errorf("Unknown error")
	}
}
