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

package bundle

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"k8s.io/klog"

	systemv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/system/v1beta1"
)

type handler struct {
	sync.Mutex
	forceRefresh chan struct{}
	cache        Response
}

func (h *handler) clean(duration time.Duration) {
	select {
	case <-h.forceRefresh:
		return
	case <-time.After(duration):
	}
	h.removeCache()
}

type CollectRequest struct {
	CollectItems []string `json:"collectItems"`
	Force        bool     `json:"force"`
}

type Response struct {
	Status     string `json:"status"`
	Sum        string `json:"sum,omitempty"`
	SubmitTime int64  `json:"generateTime,omitempty"`
	ExpireTime int64  `json:"expireTime,omitempty"`
	FilePath   string `json:"filePath,omitempty"`
}

func dumpFlows(basedir string) error {
	brListOutput, err := exec.Command("ovs-vsctl", "list-br").Output()
	if err != nil {
		return fmt.Errorf("error when collecting ovs bridge info: %w", err)
	}
	err = os.Mkdir(filepath.Join(basedir, "flows"), os.ModePerm)
	if err != nil {
		return fmt.Errorf("error when creating flows output dir: %w", err)
	}
	for _, brName := range strings.Split(strings.TrimSpace(string(brListOutput)), "\n") {
		dumpFlowOutput, err := exec.Command("ovs-ofctl", "dump-flows", brName).Output()
		if err != nil {
			return fmt.Errorf("error when dumping flows on bridge %s: %w", brName, err)
		}
		err = ioutil.WriteFile(filepath.Join(basedir, "flows", brName), dumpFlowOutput, 0644)
		if err != nil {
			return fmt.Errorf("error when creating flows output file: %w", err)
		}
	}
	return nil
}

func dumpIPTables(basedir string) error {
	iptablesOutput, err := exec.Command("iptables-save").Output()
	if err != nil {
		return fmt.Errorf("error when dumping iptables data: %w", err)
	}
	err = ioutil.WriteFile(filepath.Join(basedir, "iptables"), iptablesOutput, 0644)
	if err != nil {
		return fmt.Errorf("error when writing iptables dumps: %w", err)
	}
	return nil
}

func dumpAgentLog(basedir string) error {
	targetDir := filepath.Join(basedir, "logs")
	err := os.Mkdir(targetDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("error when creating logs output dir: %w", err)
	}
	logDir := "/var/log/antrea"
	return filepath.Walk(logDir, func(filePath string, info os.FileInfo, err error) error {
		if !info.Mode().IsRegular() {
			return nil
		}
		if !strings.HasPrefix(info.Name(), "antrea-agent") {
			return nil
		}
		targetPath := path.Join(targetDir, info.Name())
		targetFile, err := os.Create(targetPath)
		if err != nil {
			return err
		}
		defer targetFile.Close()
		logFile, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer logFile.Close()
		_, err = io.Copy(targetFile, logFile)
		return err
	})
}

func dumpOVSLog(basedir string) error {
	targetDir := filepath.Join(basedir, "logs", "ovs")
	err := os.Mkdir(targetDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("error when creating logs output dir: %w", err)
	}
	logDir := "/var/log/antrea"
	return filepath.Walk(logDir, func(filePath string, info os.FileInfo, err error) error {
		if !info.Mode().IsRegular() {
			return nil
		}
		if !strings.HasPrefix(info.Name(), "ovs") {
			return nil
		}
		targetPath := path.Join(targetDir, info.Name())
		targetFile, err := os.Create(targetPath)
		if err != nil {
			return err
		}
		defer targetFile.Close()
		logFile, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer logFile.Close()
		_, err = io.Copy(targetFile, logFile)
		return err
	})
}

func dumpIPToolInfo(basedir string) error {
	dump := func(name string) error {
		output, err := exec.Command("ip", name).Output()
		if err != nil {
			return fmt.Errorf("error when dumping %s: %w", name, err)
		}
		err = ioutil.WriteFile(filepath.Join(basedir, name), output, 0644)
		if err != nil {
			return fmt.Errorf("error when writing %s: %w", name, err)
		}
		return nil
	}
	for _, item := range []string{"route", "link", "address"} {
		if err := dump(item); err != nil {
			return err
		}
	}
	return nil
}

func packDir(basedir string, writer io.Writer) ([]byte, error) {
	hash := sha256.New()
	tarWriter := tar.NewWriter(io.MultiWriter(hash, writer))
	err := filepath.Walk(basedir, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return err
		}
		header.Name = strings.TrimPrefix(strings.ReplaceAll(filePath, basedir, ""), string(filepath.Separator))
		err = tarWriter.WriteHeader(header)
		if err != nil {
			return err
		}
		f, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tarWriter, f)
		return err
	})
	if err != nil {
		return nil, err
	}
	tarWriter.Close()
	return hash.Sum(nil), nil
}

func (h *handler) collect() error {
	startTime := time.Now()
	h.Lock()
	defer h.Unlock()

	h.cache.SubmitTime = startTime.UnixNano()
	h.cache.Status = systemv1beta1.BundleCollecting
	basedir, err := ioutil.TempDir("", "bundle_tmp*")
	if err != nil {
		return fmt.Errorf("error when creating tempdir: %w", err)
	}
	defer os.RemoveAll(basedir)

	if err := dumpFlows(basedir); err != nil {
		return err
	}
	if err := dumpIPTables(basedir); err != nil {
		return err
	}
	if err := dumpIPToolInfo(basedir); err != nil {
		return err
	}
	if err := dumpAgentLog(basedir); err != nil {
		return err
	}
	if err := dumpOVSLog(basedir); err != nil {
		return err
	}
	outputFile, err := ioutil.TempFile("", "bundle_*.tar")
	if err != nil {
		return fmt.Errorf("error when creating output tarfile: %w", err)
	}
	defer outputFile.Close()
	hashSum, err := packDir(basedir, outputFile)
	if err != nil {
		return fmt.Errorf("error when packaing bundle: %w", err)
	}
	h.cache = Response{
		Status:     systemv1beta1.BundleCollected,
		Sum:        fmt.Sprintf("%x", hashSum),
		SubmitTime: startTime.UnixNano(),
		ExpireTime: startTime.Add(time.Minute).UnixNano(),
		FilePath:   outputFile.Name(),
	}
	go h.clean(time.Minute)
	return nil
}

func (h *handler) handleFuncGet(w http.ResponseWriter, r *http.Request) {
	if err := json.NewEncoder(w).Encode(h.cache); err != nil {
		http.Error(w, fmt.Sprintf("Error when encoding response data: %v", err), http.StatusInternalServerError)
	}
}

func (h *handler) handleFuncPost(w http.ResponseWriter, r *http.Request) {
	req := new(CollectRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		http.Error(w, fmt.Sprintf("Error when parsing request body: %v", err), http.StatusBadRequest)
		return
	}
	go func() {
		if err := h.collect(); err != nil {
			klog.Errorf("Failed to collect support bundle: %v", err)
			h.cache.Status = systemv1beta1.BundleNone
		}
	}()
}

func (h *handler) handleFuncDelete(_ http.ResponseWriter, _ *http.Request) {
	h.removeCache()
}

func (h *handler) removeCache() {
	h.Lock()
	defer h.Unlock()
	if len(h.cache.FilePath) > 0 {
		os.Remove(h.cache.FilePath)
	}
	h.cache = Response{Status: systemv1beta1.BundleNone}
}

func (h *handler) HandleFunc(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleFuncGet(w, r)
	case http.MethodPost:
		h.handleFuncPost(w, r)
	case http.MethodDelete:

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// TODO: Log these issues.
func (h *handler) DownloadHandleFunc(w http.ResponseWriter, r *http.Request) {
	if h.cache.Status != systemv1beta1.BundleNone {
		http.Error(w, "No available bundle.", http.StatusNotFound)
		return
	}
	if _, err := os.Stat(h.cache.FilePath); err != nil && os.IsNotExist(err) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	f, err := os.Open(h.cache.FilePath)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer f.Close()
	if _, err := io.Copy(w, f); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func NewHandler() *handler {
	return &handler{
		forceRefresh: make(chan struct{}),
		cache: Response{
			Status: systemv1beta1.BundleNone,
		},
	}
}
