/*
Copyright 2026 Antrea Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	admissionv1 "k8s.io/api/admission/v1"
)

// isLeaderControllerServiceAccount reports whether the authenticated caller is
// the leader controller's own ServiceAccount, for an operation the leader
// controller is expected to perform on the resource (Update/Delete, never
// Create). saNamespace/saName identify the caller; leaderNamespace/leaderSAName
// identify the leader controller's ServiceAccount.
func isLeaderControllerServiceAccount(saNamespace, saName, leaderNamespace, leaderSAName string, op admissionv1.Operation) bool {
	return saNamespace == leaderNamespace && saName == leaderSAName && op != admissionv1.Create
}
