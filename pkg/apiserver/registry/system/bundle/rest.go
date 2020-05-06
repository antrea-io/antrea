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
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/afero"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/klog"
	"k8s.io/utils/exec"

	agentutil "github.com/vmware-tanzu/antrea/pkg/agent/util"
	systemv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/system/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
	"github.com/vmware-tanzu/antrea/pkg/util"
)

const bundleExpireDuration = time.Hour

var (
	defaultFS          = afero.NewOsFs()
	defaultExecutor    = exec.New()
	ofctlClientFactory = func(bridge string) ovsctl.OVSCtlClient {
		return ovsctl.NewClient(bridge)
	}
)

func NewStorage(mode string) Storage {
	bundle := &bundleREST{
		mode: mode,
		cache: &bundle{
			Bundle: systemv1beta1.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: mode},
				Status:     systemv1beta1.BundleStatusNone,
			},
		},
	}
	return Storage{
		Mode:     mode,
		Bundle:   bundle,
		Download: &downloadREST{bundle: bundle},
	}
}

// Storage contains REST resources for Bundle, includes status query and download.
type Storage struct {
	Bundle   *bundleREST
	Download *downloadREST
	Mode     string
}

var (
	_ rest.Scoper          = &bundleREST{}
	_ rest.Getter          = &bundleREST{}
	_ rest.Creater         = &bundleREST{}
	_ rest.GracefulDeleter = &bundleREST{}
)

type bundle struct {
	systemv1beta1.Bundle
	filepath string
}

// bundleREST implements REST interfaces for bundle status querying.
type bundleREST struct {
	mode         string
	statusLocker sync.RWMutex
	cancelFunc   context.CancelFunc
	cache        *bundle
}

// Create triggers a bundle generation progress. It only allows to create resource
// which has the same name with the mode. It returns metav1.Status if there is any
// error, otherwise it returns the Bundle.
func (r *bundleREST) Create(ctx context.Context, obj runtime.Object, _ rest.ValidateObjectFunc, _ *metav1.CreateOptions) (runtime.Object, error) {
	requestBundle := obj.(*systemv1beta1.Bundle)
	if requestBundle.Name != r.mode {
		return nil, errors.NewForbidden(systemv1beta1.ControllerInfoVersionResource.GroupResource(), requestBundle.Name, fmt.Errorf("only resource name \"%s\" is allowed", r.mode))
	}
	r.statusLocker.Lock()
	defer r.statusLocker.Unlock()

	if r.cancelFunc != nil {
		r.cancelFunc()
	}
	ctx, cancelFunc := context.WithCancel(context.Background())
	r.cache = &bundle{
		Bundle: systemv1beta1.Bundle{
			ObjectMeta: metav1.ObjectMeta{Name: r.mode},
			Status:     systemv1beta1.BundleStatusCollecting,
		},
	}
	r.cancelFunc = cancelFunc

	go func() {
		var err error
		var b *bundle
		if r.mode == "agent" {
			b, err = r.collectAgent(ctx)
		} else if r.mode == "controller" {
			b, err = r.collectController(ctx)
		}
		func() {
			r.statusLocker.Lock()
			defer r.statusLocker.Unlock()
			if err != nil {
				klog.Errorf("Error when collecting bundle: %v", err)
				r.cache.Status = systemv1beta1.BundleStatusNone
				return
			}
			select {
			case <-ctx.Done():
			default:
				r.cache = b
			}
		}()

		r.clean(ctx, b.filepath, bundleExpireDuration)
	}()

	return r.cache, nil
}

func (r *bundleREST) New() runtime.Object {
	return &systemv1beta1.Bundle{}
}

// Get returns current status of the bundle. It only allows to query the resource
// which has the same name of the mode.
func (r *bundleREST) Get(_ context.Context, name string, _ *metav1.GetOptions) (runtime.Object, error) {
	r.statusLocker.RLock()
	defer r.statusLocker.RUnlock()
	if r.cache.Name != name {
		return nil, errors.NewNotFound(systemv1beta1.Resource("bundle"), name)
	}
	return r.cache, nil
}

// Delete can remove the current finished bundle or cancel a running bundle
// collecting. It only allows to query the resource which has the same name of
// the mode.
func (r *bundleREST) Delete(_ context.Context, name string, _ rest.ValidateObjectFunc, _ *metav1.DeleteOptions) (runtime.Object, bool, error) {
	if name != r.mode {
		return nil, false, errors.NewNotFound(systemv1beta1.Resource("bundle"), name)
	}
	r.statusLocker.Lock()
	defer r.statusLocker.Unlock()
	if r.cancelFunc != nil {
		r.cancelFunc()
	}
	r.cache = &bundle{
		Bundle: systemv1beta1.Bundle{
			ObjectMeta: metav1.ObjectMeta{Name: r.mode},
			Status:     systemv1beta1.BundleStatusNone,
		},
	}
	return nil, true, nil
}

func (r *bundleREST) NamespaceScoped() bool {
	return false
}

func (r *bundleREST) collect(ctx context.Context, dumpers ...func(string) error) (*bundle, error) {
	basedir, err := afero.TempDir(defaultFS, "", "bundle_tmp_")
	if err != nil {
		return nil, fmt.Errorf("error when creating tempdir: %w", err)
	}
	defer defaultFS.RemoveAll(basedir)
	for _, dumper := range dumpers {
		if err := dumper(basedir); err != nil {
			return nil, err
		}
	}
	outputFile, err := defaultFS.Create(filepath.Join(afero.GetTempDir(defaultFS, ""), fmt.Sprintf("bundle_%d.tar.gz", rand.Int())))
	if err != nil {
		return nil, fmt.Errorf("error when creating output tarfile: %w", err)
	}
	defer outputFile.Close()
	hashSum, err := packDir(basedir, outputFile)
	if err != nil {
		return nil, fmt.Errorf("error when packaing bundle: %w", err)
	}

	select {
	case <-ctx.Done():
		_ = defaultFS.Remove(outputFile.Name())
		return nil, fmt.Errorf("collecting is canceled")
	default:
	}
	stat, err := outputFile.Stat()
	var fileSize int64
	if err == nil {
		fileSize = stat.Size()
	}
	creationTime := metav1.Now()
	deletionTime := metav1.NewTime(creationTime.Add(bundleExpireDuration))
	return &bundle{
		Bundle: systemv1beta1.Bundle{
			ObjectMeta: metav1.ObjectMeta{
				Name:              r.mode,
				CreationTimestamp: creationTime,
				DeletionTimestamp: &deletionTime,
			},
			Status: systemv1beta1.BundleStatusCollected,
			Sum:    fmt.Sprintf("%x", hashSum),
			Size:   uint32(fileSize),
		},
		filepath: outputFile.Name(),
	}, nil
}

func (r *bundleREST) collectAgent(ctx context.Context) (*bundle, error) {
	agentDumper := agentutil.NewDumper(defaultFS, defaultExecutor, ofctlClientFactory)
	generalDumper := util.NewDumper(defaultFS, defaultExecutor)
	return r.collect(
		ctx,
		generalDumper.DumpAgentLog,
		generalDumper.DumpOVSLog,
		agentDumper.DumpIPToolInfo,
		agentDumper.DumpIPTables,
		agentDumper.DumpFlows,
		generalDumper.DumpAddressGroups,
		generalDumper.DumpNetworkPolicies,
		generalDumper.DumpAppliedToGroups,
		generalDumper.DumpAgentInfo,
	)
}

func (r *bundleREST) collectController(ctx context.Context) (*bundle, error) {
	generalDumper := util.NewDumper(defaultFS, defaultExecutor)
	return r.collect(
		ctx,
		generalDumper.DumpControllerLog,
		generalDumper.DumpAddressGroups,
		generalDumper.DumpNetworkPolicies,
		generalDumper.DumpAppliedToGroups,
		generalDumper.DumpControllerInfo,
	)
}

func (r *bundleREST) clean(ctx context.Context, bundlePath string, duration time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(duration):
		func() {
			r.statusLocker.Lock()
			defer r.statusLocker.Unlock()
			select { // check the context again in case of cancellation when acquiring the lock.
			case <-ctx.Done():
			default:
				if r.cache.Status == systemv1beta1.BundleStatusCollected {
					r.cache = &bundle{
						Bundle: systemv1beta1.Bundle{
							ObjectMeta: metav1.ObjectMeta{Name: r.mode},
							Status:     systemv1beta1.BundleStatusNone,
						},
					}
				}
			}
		}()
	}
	defaultFS.Remove(bundlePath)
}

func packDir(dir string, writer io.Writer) ([]byte, error) {
	hash := sha256.New()
	gzWriter := gzip.NewWriter(io.MultiWriter(hash, writer))
	targzWriter := tar.NewWriter(gzWriter)
	err := afero.Walk(defaultFS, dir, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.IsDir() {
			return nil
		}
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return err
		}
		header.Name = strings.TrimPrefix(strings.ReplaceAll(filePath, dir, ""), string(filepath.Separator))
		err = targzWriter.WriteHeader(header)
		if err != nil {
			return err
		}
		f, err := defaultFS.Open(filePath)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(targzWriter, f)
		return err
	})
	if err != nil {
		return nil, err
	}
	targzWriter.Close()
	gzWriter.Close()
	return hash.Sum(nil), nil
}

var (
	_ rest.Storage         = new(downloadREST)
	_ rest.Getter          = new(downloadREST)
	_ rest.StorageMetadata = new(downloadREST)
)

// downloadREST implements the REST for downloading the bundle.
type downloadREST struct {
	bundle *bundleREST
}

func (d *downloadREST) New() runtime.Object {
	return &systemv1beta1.Bundle{}
}

func (d *downloadREST) Get(_ context.Context, _ string, _ *metav1.GetOptions) (runtime.Object, error) {
	return &bundleStream{d.bundle.cache}, nil
}

func (d *downloadREST) ProducesMIMETypes(_ string) []string {
	return []string{"application/tar+gz"}
}

func (d *downloadREST) ProducesObject(_ string) interface{} {
	return ""
}

var (
	_ rest.ResourceStreamer = new(bundleStream)
	_ runtime.Object        = new(bundleStream)
)

type bundleStream struct {
	cache *bundle
}

func (b *bundleStream) GetObjectKind() schema.ObjectKind {
	return schema.EmptyObjectKind
}

func (b *bundleStream) DeepCopyObject() runtime.Object {
	panic("bundleStream does not have DeepCopyObject")
}

func (b *bundleStream) InputStream(_ context.Context, _, _ string) (stream io.ReadCloser, flush bool, mimeType string, err error) {
	// f will be closed by invoker, no need to close in this function.
	f, err := defaultFS.Open(b.cache.filepath)
	if err != nil {
		return nil, false, "", err
	}
	return f, true, "application/tar+gz", nil
}
