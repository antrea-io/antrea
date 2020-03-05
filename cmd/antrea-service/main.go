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
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/kardianos/service"
	"golang.org/x/sys/windows"
)

const (
	systemPath = "C:\\Windows\\System32\\;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\;"

	// nodeNameEnvKey is to populate the "NODE_NAME" environment variable to Antrea Agent. This setting is to ensure
	// Antrea Agent on Windows to have the same behavior as running on Linux.
	nodeNameEnvKey = "NODE_NAME"

	serviceName        = "antrea-agent"
	serviceDisplayName = "Antrea Agent Service"
	serviceDiscription = "Run Antrea Agent as a Windows Service"

	paramForAntreaHome = "antrea-home"
	paramForLogDir     = "log-dir"

	monitorInterval = 2 * time.Second
)

// Config is the runner app config structure.
type Config struct {
	Name, DisplayName, Description string

	Dir  string
	Exec string
	Args []string
	Env  []string

	Stderr, Stdout string
	nodeName       string
	configFile     string
}

var logger service.Logger

// monitorProcess is a flag to monitor whether the antrea-agent process is running. Restart the process automatically if
// this flag is true. After antrea-agent is registered as a Windows Service,this flag is always true.
var monitorProcess = true

type program struct {
	restart chan struct{}
	exit    chan struct{}
	service service.Service

	*Config

	cmd *exec.Cmd
	ovsBridge string
}

func (p *program) Start(s service.Service) error {
	fullExec, err := exec.LookPath(p.Exec)
	if err != nil {
		return fmt.Errorf("Failed to find executable %q: %v", p.Exec, err)
	}

	p.cmd = exec.Command(fullExec, p.Args...)
	p.cmd.Dir = p.Dir
	p.cmd.Env = append(os.Environ(), p.Env...)

	if err := p.ensureHNSNetwork(); err != nil {
		logger.Errorf("Failed to create HNS Network: %v", err)
		return err
	}
	go p.run()
	// Start a goroutine to monitor the antrea-agent liveness. Re-run antrea-agent if the process is stopped abnormally.
	if monitorProcess && p.restart == nil {
		p.restart = make(chan struct{})
		go p.monitorProcess(s)
	}
	// Start a goroutine to monitor ovs-vswitchd running status, and enable/disable the OVS Extension accordingly.
	go monitorOVSState(p.exit)

	return nil
}

func (p *program) run() {
	logger.Info("Starting ", p.DisplayName)

	if p.Stderr != "" {
		f, err := os.OpenFile(p.Stderr, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0777)
		if err != nil {
			logger.Warningf("Failed to open std err %q: %v", p.Stderr, err)
			return
		}
		defer f.Close()
		p.cmd.Stderr = f
	}
	if p.Stdout != "" {
		f, err := os.OpenFile(p.Stdout, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0777)
		if err != nil {
			logger.Warningf("Failed to open std out %q: %v", p.Stdout, err)
			return
		}
		defer f.Close()
		p.cmd.Stdout = f
	}

	if p.cmd.Process != nil {
		p.cmd.Process = nil
	}
	err := p.cmd.Run()
	if err != nil {
		logger.Warningf("Error running antrea-agent: %v", err)
	}

	if monitorProcess {
		p.restart <- struct{}{}
	} else {
		p.service.Stop()
	}

	return
}

func pidAlive(pid int) bool {
	_, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return true
}

func (p *program) monitorProcess(s service.Service) {
	for {
		select {
		// exit monitoring if the service is stopped.
		case <-p.exit:
			break
		case <-p.restart:
			if p.cmd.ProcessState.Exited() && !p.cmd.ProcessState.Success() {
				// Kill the process, otherwise there might be error when re-run the process.
				p.cmd.Process.Kill()
				logger.Info("Service %s is not alive, restart the process. ", p.DisplayName)
				p.Start(s)
			}
		}
	}
}

// Send Ctrl-C to antrea-agent process to ensure it could stop gracefully. Signal.Interrupt is not supported on Windows,
// and SIGKILL is the only supported signal in Process.Signal() on Windows. Windows terminate target process immediately
// if received SIGKILL signal.
func (p *program) terminateAgent() error {
	pid := p.cmd.Process.Pid
	dll, err := windows.LoadDLL("kernel32.dll")
	if err != nil {
		return err
	}
	defer dll.Release()

	f, err := dll.FindProc("AttachConsole")
	if err != nil {
		return err
	}
	r1, _, err := f.Call(uintptr(pid))
	if r1 == 0 && err != syscall.ERROR_ACCESS_DENIED {
		return err
	}

	f, err = dll.FindProc("SetConsoleCtrlHandler")
	if err != nil {
		return err
	}
	r1, _, err = f.Call(0, 1)
	if r1 == 0 {
		return err
	}
	f, err = dll.FindProc("GenerateConsoleCtrlEvent")
	if err != nil {
		return err
	}
	r1, _, err = f.Call(windows.CTRL_C_EVENT, uintptr(pid))
	if r1 == 0 {
		return err
	}
	return nil
}

func (p *program) Stop(s service.Service) error {
	logger.Infof("Stopping %s", p.DisplayName)

	// cmd.ProcessState might be nil because antrea-agent is running, and the ProcessState should be set after the
	// process is completed. This should happen when user stop the service but not from the process crash.
	if p.cmd.ProcessState == nil || p.cmd.ProcessState.Exited() == false {
		close(p.exit)
		if err := p.terminateAgent(); err != nil {
			logger.Warningf("Error when terminating antrea-agent: %v", err)
		}
		// Kill the process in force if the process is still running after one monitor interval.
		select {
		case <-time.After(monitorInterval):
			if p.cmd.Process != nil && pidAlive(p.cmd.Process.Pid) {
				p.cmd.Process.Kill()
			}
		}
	}
	if service.Interactive() {
		os.Exit(0)
	}
	return nil
}

func getConfig(agentInstallPath, agentLogDir string) (*Config, error) {
	hostName, _ := os.Hostname()

	// Ensure the binary, configuration file and log directory exist at the specified locations.
	agentBinPath := agentInstallPath + "\\antrea-agent.exe"
	if _, err := os.Stat(agentBinPath); err != nil {
		return nil, err
	}
	agentConfigFile := agentInstallPath + "\\conf\\antrea-agent.conf"
	if _, err := os.Stat(agentConfigFile); err != nil {
		return nil, err
	}
	if _, err := os.Stat(agentLogDir); err != nil {
		return nil, err
	}
	agentLogPath := agentLogDir + "\\antrea-agent.log"

	conf := &Config{
		Name:        serviceName,
		DisplayName: serviceDisplayName,
		Description: serviceDiscription,
		Dir:         agentInstallPath,
		Exec:        agentBinPath,
		Args:        []string{"--config", agentConfigFile},
		// Add NODE_NAME as an environment variable. It is used to keep the same behavior when running Antrea Agent as a
		// Pod. Antrea Agent will leverage this variable to filter local configurations.
		Env: []string{
			fmt.Sprintf("PATH=%s", systemPath),
			fmt.Sprintf("%s=%s", nodeNameEnvKey, strings.ToLower(hostName)),
		},
		Stderr:     agentLogPath,
		Stdout:     agentLogPath,
		nodeName:   hostName,
		configFile: agentConfigFile,
	}
	return conf, nil
}

// To register antrea-agent as a Windows Service, run this command with parameter "--service-control install", e.g.
// .\antrea-service.exe --antrea-home "C:\antrea" --log-dir "C:\antrea\logs" --service-control install
func main() {
	svcFlag := flag.String("service-control", "", "Control the antrea-agent Service.")
	// A flag to enable monitoring antrea-agent. The default value is true. If antrea-agent is not expected to restart
	// automatically after the process is killed, set the flag as "false". This flag could be configured only when running
	// the binary directly.
	monitorFlag := flag.String("monitor-process", "true", "Monitor Antrea agent liveness and restart the process if it is down.")
	binPathFlag := flag.String(paramForAntreaHome, "C:\\antrea", "Directory to find Antrea Agent binary.")
	logDirFlag := flag.String(paramForLogDir, "C:\\antrea\\logs", "Log directory for Antrea Agent.")
	flag.Parse()

	args := []string{
		fmt.Sprintf("--%s", paramForAntreaHome), *binPathFlag,
		fmt.Sprintf("--%s", paramForLogDir), *logDirFlag,
	}

	config, err := getConfig(*binPathFlag, *logDirFlag)
	if err != nil {
		log.Fatal(err)
	}

	svcConfig := &service.Config{
		Name:        config.Name,
		DisplayName: config.DisplayName,
		Description: config.Description,
		Arguments:   args,
	}

	prg := &program{
		exit: make(chan struct{}),

		Config: config,
	}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}
	prg.service = s

	errs := make(chan error, 5)
	logger, err = s.Logger(errs)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			err := <-errs
			if err != nil {
				log.Print(err)
			}
		}
	}()

	if len(*svcFlag) != 0 {
		err := service.Control(s, *svcFlag)
		if err != nil {
			log.Printf("Valid actions: %q\n", service.ControlAction)
			log.Fatal(err)
		}
		return
	}
	if len(*monitorFlag) != 0 {
		monitorProcess = *monitorFlag == "true"
	}
	err = s.Run()
	if err != nil {
		logger.Error(err)
	}
}
