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

package controllerinfo

import (
	"encoding/json"
	"io"
	"io/ioutil"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/common"
	clusterinfo "github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/v1beta1"
)

// Response includes all data fields of clusterinfo.AntreaControllerInfo, but
// removes the resource meta fields.
type Response struct {
	Version                     string                                  `json:"version,omitempty"`                     // Antrea binary version
	PodRef                      corev1.ObjectReference                  `json:"podRef,omitempty"`                      // The Pod that Antrea Controller is running in
	NodeRef                     corev1.ObjectReference                  `json:"nodeRef,omitempty"`                     // The Node that Antrea Controller is running in
	ServiceRef                  corev1.ObjectReference                  `json:"serviceRef,omitempty"`                  // Antrea Controller Service
	NetworkPolicyControllerInfo clusterinfo.NetworkPolicyControllerInfo `json:"networkPolicyControllerInfo,omitempty"` // Antrea Controller NetworkPolicy information
	ConnectedAgentNum           int32                                   `json:"connectedAgentNum,omitempty"`           // Number of agents which are connected to this controller
	ControllerConditions        []clusterinfo.ControllerCondition       `json:"controllerConditions,omitempty"`        // Controller condition contains types like ControllerHealthy
}

func Transform(reader io.Reader, _ bool, _ map[string]string) (interface{}, error) {
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	klog.Infof("version transform received: %s", string(b))
	controllerInfo := new(clusterinfo.AntreaControllerInfo)
	err = json.Unmarshal(b, controllerInfo)
	if err != nil {
		return nil, err
	}
	resp := &Response{
		Version:                     controllerInfo.Version,
		PodRef:                      controllerInfo.PodRef,
		NodeRef:                     controllerInfo.NodeRef,
		ServiceRef:                  controllerInfo.ServiceRef,
		NetworkPolicyControllerInfo: controllerInfo.NetworkPolicyControllerInfo,
		ConnectedAgentNum:           controllerInfo.ConnectedAgentNum,
		ControllerConditions:        controllerInfo.ControllerConditions,
	}
	return resp, nil
}

var _ common.TableOutput = new(Response)

func (r Response) GetTableHeader() []string {
	return []string{"POD", "NODE", "STATUS", "NETWORK-POLICIES", "ADDRESS-GROUPS", "APPLIED-TO-GROUPS", "CONNECTED-AGENTS"}
}

func (r Response) GetControllerConditionStr() string {
	if r.ControllerConditions == nil {
		return ""
	}
	controllerCondition := "Healthy"
	for _, cond := range r.ControllerConditions {
		if cond.Status == corev1.ConditionUnknown {
			controllerCondition = "Unknown"
		}
		if cond.Status == corev1.ConditionFalse {
			return "Unhealthy"
		}
	}
	return controllerCondition
}

func (r Response) GetTableRow(maxColumnLength int) []string {
	return []string{r.PodRef.Namespace + "/" + r.PodRef.Name,
		r.NodeRef.Name,
		r.GetControllerConditionStr(),
		common.Int32ToString(r.NetworkPolicyControllerInfo.NetworkPolicyNum),
		common.Int32ToString(r.NetworkPolicyControllerInfo.AddressGroupNum),
		common.Int32ToString(r.NetworkPolicyControllerInfo.AppliedToGroupNum),
		common.Int32ToString(r.ConnectedAgentNum)}
}

func (r Response) SortRows() bool {
	return true
}
