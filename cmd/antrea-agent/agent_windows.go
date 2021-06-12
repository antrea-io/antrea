package main

import (
	"os/exec"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// Initializer knows how to setup host the plugin for self-registration
type ServiceInitializer struct {
	serviceNameFlag  string
}

func newServiceInitializer(
	serviceNameFlag  string) *ServiceInitializer {
	return &ServiceInitializer{
		serviceNameFlag:     serviceNameFlag,
	}
}

func getServicePath() (string, error) {
	p, err := exec.LookPath(os.Args[0])
	if err != nil {
		return "", err
	}
	return filepath.Abs(p)
}

// registerService is an entrypoint early in the daemon startup
// to handle registering against Windows Service Control Manager (SCM).
func (i *Initializer) registerServiceforOS() error {

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
		DisplayName:  "Antrea",
		Description:  "Container network plugin",
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