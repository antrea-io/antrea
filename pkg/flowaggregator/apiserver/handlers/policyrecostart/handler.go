// Copyright 2022 Antrea Authors.
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

// The simulator binary is responsible to run simulated nodes for antrea agent.
// It watches NetworkPolicies, AddressGroups and AppliedToGroups from antrea
// controller and prints the events of these resources to log.

package policyrecostart

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"net/http"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/flowaggregator/querier"
)

// Response is the response struct of policyReco start command.
type Response struct {
	Result string `json:"result,omitempty"`
}

func HandleFunc(faq querier.FlowAggregatorQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var arguments []string
		recoType := r.URL.Query().Get("type")
		limit := r.URL.Query().Get("limit")
		option := r.URL.Query().Get("option")
		startTime := r.URL.Query().Get("start_time")
		endTime := r.URL.Query().Get("end_time")
		nsAllowList := r.URL.Query().Get("ns_allow_list")
		rmLabels := r.URL.Query().Get("rm_labels")
		toServices := r.URL.Query().Get("to_services")
		if recoType != "" {
			if recoType != "initial" && recoType != "subsequent" {
				http.Error(w, "recommendation type should be 'initial' or 'subsequent'.", http.StatusBadRequest)
				return
			}
			arguments = append(arguments, "--type", recoType)
		}
		if limit != "" {
			limit_int, err := strconv.Atoi(limit)
			if err != nil || limit_int < 0 {
				http.Error(w, "limit should be an integer >= 0.", http.StatusBadRequest)
				return
			}
			arguments = append(arguments, "--limit", limit)
		}
		if option != "" {
			if option != "1" && option != "2" && option != "3" {
				http.Error(w, "option of network isolation preference should be 1 or 2 or 3.", http.StatusBadRequest)
				return
			}
			arguments = append(arguments, "--option", option)
		}
		if startTime != "" {
			_, err := time.Parse("2006-01-02 15:04:05", startTime)
			if err != nil {
				http.Error(w, "start_time should be in 'YYYY-MM-DD hh:mm:ss' format, for example: 2006-01-02 15:04:05.", http.StatusBadRequest)
				return
			}
			arguments = append(arguments, "--start_time", startTime)
		}
		if endTime != "" {
			_, err := time.Parse("2006-01-02 15:04:05", endTime)
			if err != nil {
				http.Error(w, "end_time should be in 'YYYY-MM-DD hh:mm:ss' format, for example: 2006-01-02 15:04:05.", http.StatusBadRequest)
				return
			}
			arguments = append(arguments, "--end_time", endTime)
		}
		if nsAllowList != "" {
			var parsedNsAllowList []string
			err := json.Unmarshal([]byte(nsAllowList), &parsedNsAllowList)
			if err != nil {
				http.Error(w, "ns_allow_list should be a list of namespace string.", http.StatusBadRequest)
				return
			}
			arguments = append(arguments, "--ns_allow_list", nsAllowList)
		}
		if rmLabels != "" {
			if rmLabels != "true" && rmLabels != "false" {
				http.Error(w, "remove anto-generated labels should be 'true' or 'false'.", http.StatusBadRequest)
				return
			}
			arguments = append(arguments, "--rm_labels", rmLabels)
		}
		if toServices != "" {
			if toServices != "true" && toServices != "false" {
				http.Error(w, "to_services option should be 'true' or 'false'.", http.StatusBadRequest)
				return
			}
			arguments = append(arguments, "--to_services", toServices)
		}
		driverCoreRequest := r.URL.Query().Get("driver_core_request")
		if driverCoreRequest == "" {
			driverCoreRequest = "200m"
		}
		driverMemory := r.URL.Query().Get("driver_memory")
		if driverMemory == "" {
			driverMemory = "512M"
		}
		executorInstancesStr := r.URL.Query().Get("executor_instances")
		executorInstances := int32(1)
		if executorInstancesStr != "" {
			executorInstancesInt, err := strconv.ParseInt(executorInstancesStr, 10, 32)
			if err != nil || executorInstancesInt < 0 {
				http.Error(w, "executor instances should be an integer >= 0.", http.StatusBadRequest)
				return
			}
			executorInstances = int32(executorInstancesInt)
		}
		executorCoreRequest := r.URL.Query().Get("executor_core_request")
		if executorCoreRequest == "" {
			executorCoreRequest = "200m"
		}
		executorMemory := r.URL.Query().Get("executor_memory")
		if executorMemory == "" {
			executorMemory = "512M"
		}
		recoID, err := faq.StartPolicyRecommendation(arguments, driverCoreRequest, driverMemory, executorCoreRequest, executorMemory, executorInstances)
		result := fmt.Sprintf("A new policy recommendation job is created successfully, id is %s\n", recoID)
		if err != nil {
			result = fmt.Sprintf("Error when creating a new policy recommendation job: %v\n", err)
		}
		err = json.NewEncoder(w).Encode(Response{result})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.Errorf("Error when encoding start recommendation result to json: %v", err)
		}
	}
}
