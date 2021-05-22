// +build windows

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

package main

import (
	"fmt"
	"strings"
	"os/exec"


	"k8s.io/component-base/featuregate"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

)

func (o *Options) checkUnsupportedFeatures() error {
	var unsupported []string

	// First check feature gates.
	for f, enabled := range o.config.FeatureGates {
		if enabled && !features.SupportedOnWindows(featuregate.Feature(f)) {
			unsupported = append(unsupported, f)
		}
	}

	if o.config.OVSDatapathType != string(ovsconfig.OVSDatapathSystem) {
		unsupported = append(unsupported, "OVSDatapathType: "+o.config.OVSDatapathType)
	}
	_, encapMode := config.GetTrafficEncapModeFromStr(o.config.TrafficEncapMode)
	if encapMode != config.TrafficEncapModeEncap {
		unsupported = append(unsupported, "TrafficEncapMode: "+encapMode.String())
	}
	if o.config.TunnelType == ovsconfig.GRETunnel {
		unsupported = append(unsupported, "TunnelType: "+o.config.TunnelType)
	}
	if o.config.EnableIPSecTunnel {
		unsupported = append(unsupported, "IPsecTunnel")
	}

	if unsupported != nil {
		return fmt.Errorf("unsupported features on Windows: {%s}", strings.Join(unsupported, ", "))
	}

	if !features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		klog.Warning("AntreaProxy is not enabled. NetworkPolicies might not be enforced correctly for Service traffic!")
	}
	return nil
}

func registerService() error {
	p, err := getServicePath()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	c := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  "Containerd",
		Description:  "Container runtime",
	}

	// Configure the service to launch with the arguments that were just passed.
	args := []string{"--run-service"}
	for _, a := range os.Args[1:] {
		if a != "--register-service" && a != "--unregister-service" {
			args = append(args, a)
		}
	}

	s, err := m.CreateService(serviceNameFlag, p, c, args...)
	if err != nil {
		return err
	}
	defer s.Close()

	// See http://stackoverflow.com/questions/35151052/how-do-i-configure-failure-actions-of-a-windows-service-written-in-go
	const (
		scActionNone    = 0
		scActionRestart = 1

		serviceConfigFailureActions = 2
	)

	type serviceFailureActions struct {
		ResetPeriod  uint32
		RebootMsg    *uint16
		Command      *uint16
		ActionsCount uint32
		Actions      uintptr
	}

	type scAction struct {
		Type  uint32
		Delay uint32
	}
	t := []scAction{
		{Type: scActionRestart, Delay: uint32(15 * time.Second / time.Millisecond)},
		{Type: scActionRestart, Delay: uint32(15 * time.Second / time.Millisecond)},
		{Type: scActionNone},
	}
	lpInfo := serviceFailureActions{ResetPeriod: uint32(24 * time.Hour / time.Second), ActionsCount: uint32(3), Actions: uintptr(unsafe.Pointer(&t[0]))}
	err = windows.ChangeServiceConfig2(s.Handle, serviceConfigFailureActions, (*byte)(unsafe.Pointer(&lpInfo)))
	if err != nil {
		return err
	}

	return nil
}

func getServicePath() (string, error) {
	p, err := exec.LookPath(os.Args[0])
	if err != nil {
		return "", err
	}
	return filepath.Abs(p)
}

func unregisterService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceNameFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	err = s.Delete()
	if err != nil {
		return err
	}
	return nil
}

// registerUnregisterService is an entrypoint early in the daemon startup
// to handle (un-)registering against Windows Service Control Manager (SCM).
// It returns an indication to stop on successful SCM operation, and an error.
func registerUnregisterService(root string) (bool, error) {

	if unregisterServiceFlag {
		if registerServiceFlag {
			return true, errors.Wrap(errdefs.ErrInvalidArgument, "--register-service and --unregister-service cannot be used together")
		}
		return true, unregisterService()
	}

	if registerServiceFlag {
		return true, registerService()
	}
	return false, nil
}



