// Copyright 2023 Antrea Authors
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

package apistorage

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	apiextinstall "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	antreaCRDAlfa        = createMockCRD("Alfa", "AlfaList", "alfas", "alfa", "crd.antrea.io", map[string]bool{"v1alpha1": false, "v1beta1": true}, "999")
	updatedAntreaCRDAlfa = createMockCRD("Alfa", "AlfaList", "alfas", "alfa", "crd.antrea.io", map[string]bool{"v1alpha1": false, "v1beta1": false, "v1": true}, "1000")
	antreaCRDBravo       = createMockCRD("Bravo", "BravoList", "bravos", "bravo", "crd.antrea.io", map[string]bool{"v1beta1": true}, "999")
	nonAntreaCRDCharlie  = createMockCRD("Charlie", "CharlieList", "charlies", "charlie", "crd.misc.io", map[string]bool{"v1beta1": true}, "999")
	alfa1                = createMockCRDObject("crd.antrea.io/v1beta1", "Alfa", "alfa1", "999")
	alfa2                = createMockCRDObject("crd.antrea.io/v1beta1", "Alfa", "alfa2", "999")
	updatedAlfa2         = createMockCRDObject("crd.antrea.io/v1beta1", "Alfa", "alfa2", "1000")
	bravo1               = createMockCRDObject("crd.antrea.io/v1beta1", "Bravo", "bravo1", "999")
)

func createMockCRD(kind, listKind, plural, singular, group string, versions map[string]bool, resourceVersion string) *apiextv1.CustomResourceDefinition {
	crd := &apiextv1.CustomResourceDefinition{}
	var crdVersions []apiextv1.CustomResourceDefinitionVersion
	var crdStoredVersions []string
	for version, served := range versions {
		crdVersions = append(crdVersions, apiextv1.CustomResourceDefinitionVersion{
			Name:    version,
			Served:  served,
			Storage: served,
		})
		// Add every version to StoredVersions to mock that the CRD has objects stored in multiple versions.
		crdStoredVersions = append(crdStoredVersions, version)
	}

	crd.SetName(fmt.Sprintf("%s.%s", plural, group))
	crd.Spec = apiextv1.CustomResourceDefinitionSpec{
		Group: group,
		Names: apiextv1.CustomResourceDefinitionNames{
			Kind:     kind,
			ListKind: listKind,
			Plural:   plural,
			Singular: singular,
		},
		Versions: crdVersions,
	}
	crd.Status.StoredVersions = crdStoredVersions
	crd.ResourceVersion = resourceVersion
	return crd
}

func createMockCRDObject(apiVersion, kind, name, resourceVersion string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion(apiVersion)
	obj.SetNamespace("default")
	obj.SetName(name)
	obj.SetKind(kind)
	obj.SetResourceVersion(resourceVersion)
	return obj
}

func TestCommands(t *testing.T) {
	tests := []struct {
		name           string
		crdsToUpgrade  []string
		originalCRDs   []client.Object
		expectedOutput string
	}{
		{
			name:         "Upgrade all CRDs",
			originalCRDs: []client.Object{antreaCRDAlfa, antreaCRDBravo, nonAntreaCRDCharlie, alfa1, alfa2, bravo1},
			expectedOutput: `Skip upgrading CRD "bravos.crd.antrea.io" since it only has one version.
Upgrading 2 objects of CRD "alfas.crd.antrea.io".
Successfully upgraded 2 objects of CRD "alfas.crd.antrea.io".
`,
		},
		{
			name:          "Upgrade a CRD",
			crdsToUpgrade: []string{"alfas.crd.antrea.io"},
			originalCRDs:  []client.Object{antreaCRDAlfa, antreaCRDBravo, nonAntreaCRDCharlie, alfa1, alfa2, bravo1},
			expectedOutput: `Upgrading 2 objects of CRD "alfas.crd.antrea.io".
Successfully upgraded 2 objects of CRD "alfas.crd.antrea.io".
`,
		},
		{
			name:          "Upgrade some CRDs",
			crdsToUpgrade: []string{"alfas.crd.antrea.io", "bravos.crd.antrea.io"},
			originalCRDs:  []client.Object{antreaCRDAlfa, antreaCRDBravo, nonAntreaCRDCharlie, alfa1, alfa2, bravo1},
			expectedOutput: `Skip upgrading CRD "bravos.crd.antrea.io" since it only has one version.
Upgrading 2 objects of CRD "alfas.crd.antrea.io".
Successfully upgraded 2 objects of CRD "alfas.crd.antrea.io".
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			cmd := NewCommand()
			cmd.SetErr(buf)

			scheme := runtime.NewScheme()
			apiextinstall.Install(scheme)
			opts.k8sClient = fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.originalCRDs...).
				Build()

			args := []string{"--dry-run"}
			if len(tt.crdsToUpgrade) != 0 {
				args = append(args, fmt.Sprintf("--crds=%s", strings.Join(tt.crdsToUpgrade, ",")))
				cmd.SetArgs(args)
			}

			assert.NoError(t, cmd.Execute())
			assert.Equal(t, tt.expectedOutput, buf.String())
		})
	}
}

func TestUpgradeCRDObject(t *testing.T) {
	buf := new(bytes.Buffer)
	cmd := NewCommand()
	cmd.SetErr(buf)

	scheme := runtime.NewScheme()
	apiextinstall.Install(scheme)
	opts.k8sClient = fake.NewClientBuilder().
		WithObjects(updatedAlfa2).
		WithScheme(scheme).
		Build()

	assert.EqualError(t, upgradeCRDObject(cmd.ErrOrStderr(), opts.k8sClient, antreaCRDAlfa, *alfa1), `alfas.crd.antrea.io "alfa1" not found`)
	assert.NoError(t, upgradeCRDObject(cmd.ErrOrStderr(), opts.k8sClient, antreaCRDAlfa, *alfa2))
	assert.Contains(t, buf.String(), `Got conflict error when upgrading object default/alfa2 of CRD "alfas.crd.antrea.io", retry upgrading.`)
}

func TestUpdateCRDStoredVersions(t *testing.T) {
	opts = &options{}
	scheme := runtime.NewScheme()
	apiextinstall.Install(scheme)
	opts.k8sClient = fake.NewClientBuilder().
		WithObjects(updatedAntreaCRDAlfa, antreaCRDBravo).
		WithScheme(scheme).
		Build()

	assert.EqualError(t, updateCRDStoredVersions(opts.k8sClient, antreaCRDAlfa), `The CRD "alfas.crd.antrea.io" unexpectedly changed during the upgrade. This means that either an object was persisted in a
non-storage version, or the storage version was changed by someone else during the upgrade process.
Please ensure that no changes to the CRDs are made during the upgrade process and re-run the command
until you no longer see this message.`)
	assert.NoError(t, updateCRDStoredVersions(opts.k8sClient, antreaCRDBravo))

	upgradedCRDEcho := &apiextv1.CustomResourceDefinition{}
	assert.NoError(t, opts.k8sClient.Get(context.TODO(), client.ObjectKey{Name: antreaCRDBravo.GetName()}, upgradedCRDEcho))
	assert.Equal(t, 1, len(upgradedCRDEcho.Status.StoredVersions))
	assert.Equal(t, "v1beta1", upgradedCRDEcho.Status.StoredVersions[0])
}
