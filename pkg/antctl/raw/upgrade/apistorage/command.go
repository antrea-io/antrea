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
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	apiextinstall "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/util/k8s"
)

var example = strings.Trim(`
  Perform a dry-run to upgrade all existing objects of Antrea CRDs to the storage API version
  $ antctl upgrade api-storage --dry-run

  Upgrade all existing objects of Antrea CRDs to the storage version
  $ antctl upgrade api-storage

  Upgrade existing AntreaAgentInfo objects to the storage version
  $ antctl upgrade api-storage --crds=antreaagentinfos.crd.antrea.io

  Upgrade existing Egress and Group objects to the storage version
  $ antctl upgrade api-storage --crds=egresses.crd.antrea.io,groups.crd.antrea.io
`, "\n")

type options struct {
	k8sClient client.Client
	crdNames  []string
	dryRun    bool
}

var opts *options

func NewCommand() *cobra.Command {
	command := &cobra.Command{
		Use:     "api-storage",
		Short:   "Upgrade existing objects of Antrea CRDs to the storage version",
		Example: example,
		RunE:    runE,
	}
	o := &options{}
	command.Flags().StringSliceVar(&o.crdNames, "crds", nil, "Specify some Antrea CRDs to upgrade")
	command.Flags().BoolVar(&o.dryRun, "dry-run", false, "Only print objects that would be upgraded")
	opts = o

	return command
}

func (o *options) complete(cmd *cobra.Command) error {
	if o.k8sClient != nil {
		return nil
	}

	scheme := runtime.NewScheme()
	apiextinstall.Install(scheme)
	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return err
	}

	o.k8sClient, err = client.New(kubeconfig, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}

	if o.dryRun {
		o.k8sClient = client.NewDryRunClient(o.k8sClient)
	}

	return nil
}

func runE(cmd *cobra.Command, _ []string) error {
	if err := opts.complete(cmd); err != nil {
		return err
	}

	writer := cmd.ErrOrStderr()
	crdNamesToUpgrade, err := getCRDNamesToUpgrade(writer, opts.k8sClient, sets.New[string](opts.crdNames...))
	if err != nil {
		return err
	}

	crdObjectsToUpgrade, err := getCRDsToUpgrade(writer, opts.k8sClient, crdNamesToUpgrade)
	if err != nil {
		return err
	}
	for _, crd := range crdObjectsToUpgrade {
		if err = upgradeCRDObjects(writer, opts.k8sClient, crd); err != nil {
			return err
		}
		if err = updateCRDStoredVersions(opts.k8sClient, crd); err != nil {
			return err
		}
	}

	return nil
}

// getAntreaCRDNames gets names of all Antrea CRDs.
func getAntreaCRDNames(k8sClient client.Client) (sets.Set[string], error) {
	crdNames := sets.New[string]()
	crdList := &apiextv1.CustomResourceDefinitionList{}
	if err := k8sClient.List(context.TODO(), crdList); err != nil {
		return nil, fmt.Errorf("failed to get CRD list: %v", err)
	}
	for _, crd := range crdList.Items {
		if strings.HasSuffix(crd.Name, "crd.antrea.io") {
			crdNames.Insert(crd.Name)
		}
	}

	return crdNames, nil
}

// getCRDNamesToUpgrade gets names of Antrea CRDs to upgrade.
func getCRDNamesToUpgrade(writer io.Writer, k8sClient client.Client, crdNamesToUpgrade sets.Set[string]) (sets.Set[string], error) {
	antreaCRDNames, err := getAntreaCRDNames(k8sClient)
	if err != nil {
		return nil, err
	}
	// If the user-provided name list of CRDs to upgrade is empty, upgrade all Antrea CRDs.
	if crdNamesToUpgrade.Len() == 0 {
		crdNamesToUpgrade = antreaCRDNames
	} else {
		// If the user-provided name list of CRDs to upgrade is not empty, and it contains CRDs without suffix
		// "crd.antrea.io", skip these CRDs.
		for name := range crdNamesToUpgrade.Difference(antreaCRDNames) {
			fmt.Fprintf(writer, "Skip CRD %q which is not created by Antrea.\n", name)
		}
		// Only upgrade the CRDs with suffix "crd.antrea.io".
		crdNamesToUpgrade = crdNamesToUpgrade.Intersection(antreaCRDNames)
	}
	return crdNamesToUpgrade, nil
}

// getCRDsToUpgrade gets a list of Antrea CRDs to upgrade.
func getCRDsToUpgrade(writer io.Writer, k8sClient client.Client, crdNamesToUpgrade sets.Set[string]) ([]*apiextv1.CustomResourceDefinition, error) {
	var crdsToUpgrade []*apiextv1.CustomResourceDefinition
	for crdName := range crdNamesToUpgrade {
		crd := &apiextv1.CustomResourceDefinition{}
		if err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: crdName}, crd); err != nil {
			return nil, fmt.Errorf("error getting CRD %q: %w", crdName, err)
		}
		// Skip the CRD that has only one version.
		if len(crd.Spec.Versions) == 1 {
			fmt.Fprintf(writer, "Skip upgrading CRD %q since it only has one version.\n", crdName)
			continue
		}
		// Skip the CRD that all stored objects are in the storage version.
		if len(crd.Status.StoredVersions) == 1 && crd.Status.StoredVersions[0] == getCRDStorageVersion(crd) {
			fmt.Fprintf(writer, "Skip upgrading CRD %q since all stored objects are in the storage version.\n", crdName)
			continue
		}
		crdsToUpgrade = append(crdsToUpgrade, crd)
	}
	return crdsToUpgrade, nil
}

// upgradeCRDObjects upgrades the existing objects of a CRD.
func upgradeCRDObjects(writer io.Writer, k8sClient client.Client, crd *apiextv1.CustomResourceDefinition) error {
	objList := &unstructured.UnstructuredList{}
	objList.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   crd.Spec.Group,
		Version: getCRDStorageVersion(crd),
		Kind:    crd.Spec.Names.ListKind,
	})

	if err := k8sClient.List(context.TODO(), objList); err != nil {
		return err
	}

	itemCount := len(objList.Items)
	if itemCount == 0 {
		return nil
	}

	fmt.Fprintf(writer, "Upgrading %d objects of CRD %q.\n", itemCount, crd.Name)
	for _, item := range objList.Items {
		if err := upgradeCRDObject(writer, k8sClient, crd, item); err != nil {
			itemNamespacedName := k8s.NamespacedName(item.GetNamespace(), item.GetName())
			if apierrors.IsNotFound(err) {
				fmt.Fprintf(writer, "Skip upgrading object %s of CRD %q which is not found.\n", itemNamespacedName, crd.Name)
			} else {
				return fmt.Errorf("error upgrading object %s of CRD %q: %w", itemNamespacedName, crd.Name, err)
			}
		}
	}
	fmt.Fprintf(writer, "Successfully upgraded %d objects of CRD %q.\n", itemCount, crd.Name)

	return nil
}

func upgradeCRDObject(writer io.Writer, k8sClient client.Client, crd *apiextv1.CustomResourceDefinition, obj unstructured.Unstructured) error {
	objToUpdate := &obj
	var updateErr, getErr error

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		updateErr = k8sClient.Update(context.TODO(), objToUpdate)
		// If there is a conflict error, update pointer "objToUpdate" to retry.
		if updateErr != nil && apierrors.IsConflict(updateErr) {
			fmt.Fprintf(writer, "Got conflict error when upgrading object %s of CRD %q, retry upgrading.\n", k8s.NamespacedName(obj.GetNamespace(), obj.GetName()), crd.Name)
			objToUpdate = &unstructured.Unstructured{}
			objToUpdate.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   crd.Spec.Group,
				Version: getCRDStorageVersion(crd),
				Kind:    crd.Spec.Names.Kind,
			})
			if getErr = k8sClient.Get(context.TODO(), client.ObjectKeyFromObject(&obj), objToUpdate); getErr != nil {
				return getErr
			}
		}
		return updateErr
	})
}

// updateCRDStoredVersions updates status.storedVersion of a CRD.
func updateCRDStoredVersions(k8sClient client.Client, crd *apiextv1.CustomResourceDefinition) error {
	copiedCRD := *crd
	copiedCRD.Status.StoredVersions = []string{getCRDStorageVersion(crd)}
	if err := k8sClient.Status().Update(context.TODO(), &copiedCRD); err != nil {
		if apierrors.IsConflict(err) {
			return newUnexpectedChangeError(crd)
		}
		return fmt.Errorf("error updating CRD %q status.storedVersion: %w", crd.Name, err)
	}
	return nil
}

func getCRDStorageVersion(crd *apiextv1.CustomResourceDefinition) string {
	storageVersion := ""
	for _, v := range crd.Spec.Versions {
		if v.Storage {
			storageVersion = v.Name
			break
		}
	}
	return storageVersion
}

func newUnexpectedChangeError(crd *apiextv1.CustomResourceDefinition) error {
	errorFmt := "The CRD %q unexpectedly changed during the upgrade. This means that either an object was persisted in a\n" +
		"non-storage version, or the storage version was changed by someone else during the upgrade process.\n" +
		"Please ensure that no changes to the CRDs are made during the upgrade process and re-run the command\n" +
		"until you no longer see this message."
	return fmt.Errorf(errorFmt, crd.Name)
}
