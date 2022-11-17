// Copyright 2022 Antrea Authors
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

package supportbundlecollection

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"antrea.io/antrea/pkg/apis/controlplane"
)

func TestCreate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		obj      runtime.Object
		expError error
	}{
		{
			name: "invalid-status-type",
			obj: runtime.Object(&controlplane.SupportBundleCollection{
				ObjectMeta: metav1.ObjectMeta{
					Name: "invalid-status-type",
				},
			}),
			expError: errors.NewBadRequest("not a SupportBundleCollectionStatus object"),
		},
		{
			name: "invalid-status-name",
			obj: runtime.Object(&controlplane.SupportBundleCollectionStatus{
				ObjectMeta: metav1.ObjectMeta{
					Name: "invalid-name",
				},
			}),
			expError: errors.NewBadRequest("name in URL does not match name in SupportBundleCollectionStatus object"),
		},
		{
			name: "unable-update",
			obj: runtime.Object(&controlplane.SupportBundleCollectionStatus{
				ObjectMeta: metav1.ObjectMeta{
					Name: "unable-update",
				},
			}),
			expError: fmt.Errorf("no Nodes status is updated"),
		},
		{
			name: "valid-status-update",
			obj: runtime.Object(&controlplane.SupportBundleCollectionStatus{
				ObjectMeta: metav1.ObjectMeta{
					Name: "valid-status-update",
				},
				Nodes: []controlplane.SupportBundleCollectionNodeStatus{
					{
						NodeName: "n1",
						NodeType: "Node",
					},
				},
			}),
			expError: nil,
		},
	} {
		statusController := &fakeStatusCollector{
			bundleCollectionStatuses: make(map[string]*controlplane.SupportBundleCollectionStatus),
		}
		r := NewStatusREST(statusController)
		rsp, err := r.Create(context.TODO(), tc.name, tc.obj, nil, &metav1.CreateOptions{})
		if tc.expError == nil {
			assert.NoError(t, err)
			assert.Equal(t, &metav1.Status{Status: metav1.StatusSuccess}, rsp)
			expStatus := tc.obj.(*controlplane.SupportBundleCollectionStatus)
			status := statusController.bundleCollectionStatuses[tc.name]
			assert.Equal(t, expStatus, status)
		} else {
			assert.Error(t, err)
			assert.True(t, strings.Contains(err.Error(), tc.expError.Error()))
		}
	}
}

type fakeStatusCollector struct {
	bundleCollectionStatuses map[string]*controlplane.SupportBundleCollectionStatus
}

func (c *fakeStatusCollector) UpdateStatus(status *controlplane.SupportBundleCollectionStatus) error {
	bundleCollectionName := status.Name
	if len(status.Nodes) == 0 {
		return fmt.Errorf("no Nodes status is updated")
	}
	c.bundleCollectionStatuses[bundleCollectionName] = status
	return nil
}
