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

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/v1beta1"
	mockmonitor "github.com/vmware-tanzu/antrea/pkg/monitor/testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var antreaAgentInfo0 v1beta1.AntreaAgentInfo = v1beta1.AntreaAgentInfo{
	ObjectMeta: metav1.ObjectMeta{
		Name: "node0-k8",
	},
	Version: "1.0",
	PodRef: corev1.ObjectReference{
		Kind:      "Pod",
		Namespace: "kube-system",
		Name:      "antrea-agent-flx99",
	},
	NodeRef: corev1.ObjectReference{
		Kind: "Node",
		Name: "node0-k8",
	},
	NodeSubnet: []string{
		"192.168.0.0/24",
	},
	OVSInfo:                     v1beta1.OVSInfo{},
	NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{},
	LocalPodNum:                 1,
	AgentConditions: []v1beta1.AgentCondition{
		{
			Type:   v1beta1.AgentHealthy,
			Status: corev1.ConditionTrue,
		},
	},
}

func TestAgentInfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testcases := map[string]struct {
		testNode           corev1.ObjectReference
		agentInfo          *v1beta1.AntreaAgentInfo
		expectedOutput     string
		expectedStatusCode int
	}{
		"AgentInfo": {
			agentInfo:          &antreaAgentInfo0,
			expectedOutput:     "{\"version\":\"1.0\",\"podRef\":{\"kind\":\"Pod\",\"namespace\":\"kube-system\",\"name\":\"antrea-agent-flx99\"},\"nodeRef\":{\"kind\":\"Node\",\"name\":\"node0-k8\"},\"ovsInfo\":{},\"networkPolicyControllerInfo\":{},\"localPodNum\":1,\"agentConditions\":[{\"type\":\"AgentHealthy\",\"status\":\"True\",\"lastHeartbeatTime\":null}]}\n",
			expectedStatusCode: http.StatusOK,
		},
	}
	for k, tc := range testcases {
		t.Run(k, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", nil)
			assert.Nil(t, err)
			recorder := httptest.NewRecorder()
			aq := mockmonitor.NewMockAgentQuerier(ctrl)
			aq.EXPECT().GetAgentInfo().Return(tc.agentInfo)
			new(AgentInfo).Handler(aq, nil).ServeHTTP(recorder, req)
			assert.Equal(t, tc.expectedStatusCode, recorder.Code, k)
			assert.Equal(t, tc.expectedOutput, recorder.Body.String(), k)
		})
	}
}
