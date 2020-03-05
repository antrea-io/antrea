// Copyright 2019 Antrea Authors
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

package healthzcheck

import (
	"fmt"
	"net/http"

	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/klog"
	"k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/server/healthz"
)

type HealthCheckClient struct {
	healthzCheckers []healthz.HealthzChecker
}

// NewHealthCheckClient constructs a Client instance for health checking.
func NewHealthCheckClient() HealthCheckClient {
	// Create health checkers for antrea agent.
	// For now there is only a ping health checker.
	// We can also add more checks to it depending on the requirements,
	// like ovs connection, antrea-controller connection.
	healthzCheckers := make([]healthz.HealthzChecker, 0)
	healthzCheckers = append(healthzCheckers, healthz.PingHealthz)
	return HealthCheckClient{
		healthzCheckers: healthzCheckers,
	}
}

func (c *HealthCheckClient) InstallHealthChecker(apiServer *genericapiserver.GenericAPIServer) error {
	for _, healthzChecker := range c.healthzCheckers {
		err := apiServer.AddHealthzChecks(healthzChecker)
		if err != nil {
			return fmt.Errorf("error when adding healthz checks: %v", err)
		}
	}
	return nil
}

func (c *HealthCheckClient) HealthCheck(r *http.Request) bool {
	klog.Infof("Begin antrea agent health check")
	for _, checker := range c.healthzCheckers {
		name := checker.Name()
		klog.V(2).Infof("Implementing health checker %s ... ", name)
		if err := checker.Check(r); err != nil {
			klog.Errorf("Error when implementing health checker %s, error: %s", checker.Name(), err)
			return false
		} else {
			klog.V(2).Infof("Successfully implemented health checker %s!", checker.Name())
		}
	}
	klog.Infof("Successfully completed antrea agent health check")
	return true
}
