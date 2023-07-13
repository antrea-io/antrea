/*
Copyright 2021 Antrea Authors.

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

package common

type ClusterID string
type ClusterSetID string

const (
	AntreaMCServiceAnnotation = "multicluster.antrea.io/imported-service"
	AntreaMCACNPAnnotation    = "multicluster.antrea.io/imported-acnp"
	GatewayAnnotation         = "multicluster.antrea.io/gateway"
	GatewayIPAnnotation       = "multicluster.antrea.io/gateway-ip"

	AntreaMCSPrefix = "antrea-mc-"

	InvalidClusterID    = ClusterID("invalid")
	InvalidClusterSetID = ClusterSetID("invalid")

	DefaultWorkerCount = 5
	// LabelIdentityWorkerCount is the number of workers used by LabelIdentityReconciler,
	// LabelIdentityExportReconciler and LabelIdentityResourceImportReconciler.
	// Using more workers for those reconcilers could have a better performance when a
	// lot of LabelIdentity events happen concurrently.
	LabelIdentityWorkerCount = 10

	EndpointIPTypeClusterIP = "ClusterIP"
	EndpointIPTypePodIP     = "PodIP"

	// ResourceExchangeQPS and ResourceExchangeBurst are used to configure the client-go
	// used by Antrea Multi-cluster resource exchange pipeline. Using higher QPS and
	// Burst, instead of default settings, could significantly improve the performance,
	// when a lot of LabelIdentity events happen concurrently.
	ResourceExchangeQPS   = 100
	ResourceExchangeBurst = 200
)
