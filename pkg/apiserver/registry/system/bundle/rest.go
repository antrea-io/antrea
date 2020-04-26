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
	"context"
	"fmt"
	"io"
	"math/rand"
	"path/filepath"
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

	systemv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/system/v1beta1"
)

const bundleExpireDuration = time.Hour

var (
	defaultFS       = afero.NewOsFs()
	defaultExecutor = exec.New()
)

var (
	_ rest.Scoper          = &statusREST{}
	_ rest.Getter          = &statusREST{}
	_ rest.Creater         = &statusREST{}
	_ rest.GracefulDeleter = &statusREST{}
)

func NewStorage(mode string) Storage {
	status := &statusREST{
		mode: mode,
		cache: &systemv1beta1.Bundle{
			ObjectMeta: metav1.ObjectMeta{Name: mode},
			Status:     systemv1beta1.BundleNone,
		},
	}
	return Storage{
		Mode:     mode,
		Status:   status,
		Download: &downloadREST{status: status},
	}
}

type Storage struct {
	Status   *statusREST
	Download *downloadREST
	Mode     string
}

type statusREST struct {
	mode         string
	statusLocker sync.RWMutex
	cancelFunc   context.CancelFunc
	cache        *systemv1beta1.Bundle
}

func (r *statusREST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
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
	r.cache = &systemv1beta1.Bundle{
		ObjectMeta: metav1.ObjectMeta{Name: r.mode},
		Status:     systemv1beta1.BundleCollecting,
	}
	r.cancelFunc = cancelFunc

	go func() {
		var err error
		var bundle *systemv1beta1.Bundle
		if r.mode == "agent" {
			bundle, err = r.collectAgent(ctx)
		} else if r.mode == "controller" {
			bundle, err = r.collectController(ctx)
		}
		func() {
			r.statusLocker.Lock()
			defer r.statusLocker.Unlock()
			if err != nil {
				klog.Errorf("Error when collecting bundle: %v", err)
				r.cache.Status = systemv1beta1.BundleNone
				return
			}
			select {
			case <-ctx.Done():
			default:
				r.cache = bundle
			}
		}()

		r.clean(ctx, bundle.FilePath, bundleExpireDuration)
	}()

	return r.cache, nil
}

func (r *statusREST) New() runtime.Object {
	return &systemv1beta1.Bundle{}
}

func (r *statusREST) Get(_ context.Context, name string, _ *metav1.GetOptions) (runtime.Object, error) {
	r.statusLocker.RLock()
	defer r.statusLocker.RUnlock()
	if r.cache.Name != name {
		return nil, errors.NewNotFound(systemv1beta1.Resource("bundle"), name)
	}
	return r.cache, nil
}

func (r *statusREST) Delete(_ context.Context, name string, _ rest.ValidateObjectFunc, _ *metav1.DeleteOptions) (runtime.Object, bool, error) {
	if name != r.mode {
		return nil, false, errors.NewNotFound(systemv1beta1.Resource("bundle"), name)
	}
	r.statusLocker.Lock()
	defer r.statusLocker.Unlock()
	if r.cancelFunc != nil {
		r.cancelFunc()
	}
	r.cache = &systemv1beta1.Bundle{
		ObjectMeta: metav1.ObjectMeta{Name: r.mode},
		Status:     systemv1beta1.BundleNone,
	}
	return nil, true, nil
}

func (r *statusREST) NamespaceScoped() bool {
	return false
}

func (r *statusREST) collect(ctx context.Context, dumpers ...func(string) error) (*systemv1beta1.Bundle, error) {
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

	creationTime := metav1.Now()
	deletionTime := metav1.NewTime(creationTime.Add(bundleExpireDuration))
	return &systemv1beta1.Bundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:              r.mode,
			CreationTimestamp: creationTime,
			DeletionTimestamp: &deletionTime,
		},
		Status:   systemv1beta1.BundleCollected,
		Sum:      fmt.Sprintf("%x", hashSum),
		FilePath: outputFile.Name(),
	}, nil
}

func (r *statusREST) collectAgent(ctx context.Context) (*systemv1beta1.Bundle, error) {
	return r.collect(
		ctx,
		dumpAgentLog,
		dumpOVSLog,
		dumpIPToolInfo,
		dumpIPTables,
		dumpFlows,
		dumpAddressGroups,
		dumpNetworkPolicies,
		dumpAppliedToGroups,
		dumpAgentInfo,
	)
}

func (r *statusREST) collectController(ctx context.Context) (*systemv1beta1.Bundle, error) {
	return r.collect(
		ctx,
		dumpControllerLog,
		dumpAddressGroups,
		dumpNetworkPolicies,
		dumpAppliedToGroups,
		dumpControllerInfo,
	)
}

func (r *statusREST) clean(ctx context.Context, bundlePath string, duration time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(duration):
		func() {
			r.statusLocker.Lock()
			defer r.statusLocker.Unlock()
			select {
			case <-ctx.Done():
			default:
				if r.cache.Status == systemv1beta1.BundleCollected {
					r.cache = &systemv1beta1.Bundle{
						ObjectMeta: metav1.ObjectMeta{Name: r.mode},
						Status:     systemv1beta1.BundleNone,
					}
				}
			}
		}()
	}
	defaultFS.Remove(bundlePath)
}

var (
	_ rest.Storage         = new(downloadREST)
	_ rest.Getter          = new(downloadREST)
	_ rest.StorageMetadata = new(downloadREST)
)

type downloadREST struct {
	status *statusREST
}

func (d *downloadREST) New() runtime.Object {
	return &systemv1beta1.Bundle{}
}

func (d *downloadREST) Get(_ context.Context, _ string, _ *metav1.GetOptions) (runtime.Object, error) {
	return &bundleStream{d.status.cache}, nil
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
	cache *systemv1beta1.Bundle
}

func (b *bundleStream) GetObjectKind() schema.ObjectKind {
	return schema.EmptyObjectKind
}

func (b *bundleStream) DeepCopyObject() runtime.Object {
	panic("bundleStream does not have DeepCopyObject")
}

func (b *bundleStream) InputStream(ctx context.Context, apiVersion, acceptHeader string) (stream io.ReadCloser, flush bool, mimeType string, err error) {
	// f will be closed by invoker, no need to close in this function.
	f, err := defaultFS.Open(b.cache.FilePath)
	if err != nil {
		return nil, false, "", err
	}
	return f, true, "application/tar+gz", nil
}
