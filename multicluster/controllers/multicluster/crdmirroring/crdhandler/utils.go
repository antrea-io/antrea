// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package crdhandler

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcsv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/crdmirroring/types"
)

func setMetaData(legacyObj, newObj metav1.Object) {
	newObj.SetLabels(labelsDeepCopy(legacyObj))
	newObj.SetName(legacyObj.GetName())
	newObj.SetNamespace(legacyObj.GetNamespace())
	newObj.SetAnnotations(map[string]string{types.ManagedBy: types.ControllerName})
	if legacyObj.GetName() == mcsv1alpha2.WellKnownClusterClaimID {
		newObj.SetName(mcsv1alpha1.WellKnownClusterPropertyID)
	} else {
		newObj.SetName(legacyObj.GetName())
	}
}

func labelsDeepCopy(obj metav1.Object) map[string]string {
	res := map[string]string{}
	for label, val := range obj.GetLabels() {
		res[label] = val
	}
	return res
}
