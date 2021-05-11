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

package loglevel

import (
	"encoding/json"
	"net/http"
	"strconv"

	"k8s.io/klog/v2"

	"github.com/vmware-tanzu/antrea/pkg/log"
)

// HandleFunc returns the function which can handle the /loglevel API request.
func HandleFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		level := r.URL.Query().Get("level")
		if level != "" {
			err := log.SetLogLevel(level)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			levelNum, _ := strconv.Atoi(log.GetCurrentLogLevel())
			err := json.NewEncoder(w).Encode(levelNum)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				klog.Errorf("Error when encoding log level to json: %v", err)
			}
		}
	}
}
