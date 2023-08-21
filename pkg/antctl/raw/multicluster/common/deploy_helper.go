// Copyright 2022 Antrea Authors
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

package common

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/restmapper"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
)

const (
	LeaderRole = "leader"
	MemberRole = "member"

	latestVersionURL = "https://raw.githubusercontent.com/antrea-io/antrea/main/multicluster/build/yamls"
	downloadURL      = "https://github.com/antrea-io/antrea/releases/download"
	leaderYAML       = "antrea-multicluster-leader.yml"
	memberYAML       = "antrea-multicluster-member.yml"
)

var httpGet = http.Get
var getAPIGroupResources = getAPIGroupResourcesWrapper

func generateManifests(role string, version string) ([]string, error) {
	var manifests []string
	switch role {
	case LeaderRole:
		manifests = []string{
			fmt.Sprintf("%s/%s", latestVersionURL, leaderYAML),
		}
		if version != "latest" {
			manifests = []string{
				fmt.Sprintf("%s/%s/%s", downloadURL, version, leaderYAML),
			}
		}
	case MemberRole:
		manifests = []string{
			fmt.Sprintf("%s/%s", latestVersionURL, memberYAML),
		}
		if version != "latest" {
			manifests = []string{
				fmt.Sprintf("%s/%s/%s", downloadURL, version, memberYAML),
			}
		}
	default:
		return nil, fmt.Errorf("invalid role: %s", role)
	}
	return manifests, nil
}

func DecodeYAML(cmd *cobra.Command, apiGroupResources []*restmapper.APIGroupResources,
	dynamicClient dynamic.Interface, content []byte) (map[dynamic.ResourceInterface]*unstructured.Unstructured, error) {
	var err error
	decoder := yamlutil.NewYAMLOrJSONDecoder(bytes.NewReader([]byte(content)), 100)
	unstructuredObjs := map[dynamic.ResourceInterface]*unstructured.Unstructured{}
	for {
		var rawObj runtime.RawExtension
		if err = decoder.Decode(&rawObj); err != nil {
			break
		}

		obj, gvk, err := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme).Decode(rawObj.Raw, nil, nil)
		if err != nil {
			return nil, err
		}
		unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
		if err != nil {
			return nil, err
		}

		unstructuredObj := &unstructured.Unstructured{Object: unstructuredMap}
		mapper := restmapper.NewDiscoveryRESTMapper(apiGroupResources)
		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return nil, err
		}
		var dri dynamic.ResourceInterface
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			dri = dynamicClient.Resource(mapping.Resource).Namespace(unstructuredObj.GetNamespace())
		} else {
			dri = dynamicClient.Resource(mapping.Resource)
		}
		unstructuredObjs[dri] = unstructuredObj
	}

	return unstructuredObjs, nil
}

func createResources(cmd *cobra.Command, apiGroupResources []*restmapper.APIGroupResources, dynamicClient dynamic.Interface, content []byte) error {
	unstructuredObjs, err := DecodeYAML(cmd, apiGroupResources, dynamicClient, content)
	if err != nil {
		return err
	}

	for dri, unstructuredObj := range unstructuredObjs {
		if _, err := dri.Create(context.TODO(), unstructuredObj, metav1.CreateOptions{}); err != nil {
			if !kerrors.IsAlreadyExists(err) {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s/%s already exists\n", unstructuredObj.GetKind(), unstructuredObj.GetName())
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "%s/%s created\n", unstructuredObj.GetKind(), unstructuredObj.GetName())
		}
	}
	return nil
}

func deleteResources(cmd *cobra.Command, apiGroupResources []*restmapper.APIGroupResources, dynamicClient dynamic.Interface, content []byte) error {
	unstructuredObjs, err := DecodeYAML(cmd, apiGroupResources, dynamicClient, content)
	if err != nil {
		return err
	}

	for dri, unstructuredObj := range unstructuredObjs {
		err := dri.Delete(context.TODO(), unstructuredObj.GetName(), metav1.DeleteOptions{})
		if err != nil && !kerrors.IsNotFound(err) {
			return err
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "%s/%s deleted\n", unstructuredObj.GetKind(), unstructuredObj.GetName())
		}
	}
	return nil
}

func GetClients(cmd *cobra.Command) (*kubernetes.Clientset, *dynamic.DynamicClient, error) {
	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return nil, nil, err
	}

	k8sClient, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		return nil, nil, err
	}
	dynamicClient, err := dynamic.NewForConfig(kubeconfig)
	if err != nil {
		return nil, nil, err
	}
	return k8sClient, dynamicClient, nil
}

func DeployOrRemove(cmd *cobra.Command, role string, version string, namespace string, filename string, action string) error {
	k8sClient, dynamicClient, err := GetClients(cmd)
	if err != nil {
		return err
	}
	apiGroupResources, err := getAPIGroupResources(k8sClient)
	if err != nil {
		return err
	}

	if filename != "" {
		content, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		err = checkAndExecute(cmd, k8sClient, dynamicClient, apiGroupResources, content, action, role)
		if err != nil {
			return err
		}
	} else {
		manifests, err := generateManifests(role, version)
		if err != nil {
			return err
		}
		for _, manifest := range manifests {
			// #nosec G107
			resp, err := httpGet(manifest)
			if err != nil {
				return err
			}
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			content := string(b)
			if role == LeaderRole && strings.Contains(manifest, "namespaced") && namespace != DefaultLeaderNamespace {
				content = strings.ReplaceAll(content, DefaultLeaderNamespace, namespace)
			}
			if role == MemberRole && strings.Contains(manifest, "member") && namespace != DefaultMemberNamespace {
				content = strings.ReplaceAll(content, DefaultMemberNamespace, namespace)
			}
			err = checkAndExecute(cmd, k8sClient, dynamicClient, apiGroupResources, []byte(content), action, role)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func checkAndExecute(cmd *cobra.Command,
	k8sClient *kubernetes.Clientset,
	dynamicClient *dynamic.DynamicClient,
	apiGroupResources []*restmapper.APIGroupResources,
	content []byte,
	action string, role string) error {
	switch action {
	case "deploy":
		if err := createResources(cmd, apiGroupResources, dynamicClient, content); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Antrea Multi-cluster successfully deployed\n")
	case "remove":
		if role == LeaderRole {
			if err := cleanupLeader(cmd); err != nil {
				return err
			}
		}
		if role == MemberRole {
			if err := cleanupMember(cmd); err != nil {
				return err
			}
		}
		if err := deleteResources(cmd, apiGroupResources, dynamicClient, content); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Antrea Multi-cluster successfully deleted\n")
	}
	return nil
}

// cleanupLeader empty the finalizer of all ResourceExports in the leader cluster.
func cleanupLeader(cmd *cobra.Command) error {
	k8sClient, err := NewClient(cmd)
	if err != nil {
		return err
	}

	ctx := context.TODO()
	resExports := &mcv1alpha1.ResourceExportList{}
	err = k8sClient.List(ctx, resExports, &client.ListOptions{})
	if err != nil {
		return err
	}
	for _, resExport := range resExports.Items {
		if len(resExport.Finalizers) > 0 {
			resExport.Finalizers = []string{}
			err = k8sClient.Update(ctx, &resExport, &client.UpdateOptions{})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// cleanupMember deletes all resources which are automatically created by antrea-mc-controler
// in the member cluster.
func cleanupMember(cmd *cobra.Command) error {
	k8sClient, err := NewClient(cmd)
	if err != nil {
		return err
	}
	// Get all ACNPs created by antrea-mc-controller and delete them.
	ctx := context.TODO()
	acnps := &v1beta1.ClusterNetworkPolicyList{}
	if err = k8sClient.List(ctx, acnps, &client.ListOptions{}); err != nil {
		return err
	}
	acnpsCreatedByAntreaMC := []v1beta1.ClusterNetworkPolicy{}
	for _, acnp := range acnps.Items {
		if acnp.Annotations[AntreaMCACNPAnnotation] == "true" {
			acnpsCreatedByAntreaMC = append(acnpsCreatedByAntreaMC, acnp)
		}
	}
	for _, acnp := range acnpsCreatedByAntreaMC {
		acnpTmp := acnp
		err := k8sClient.Delete(ctx, &acnpTmp, &client.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if err == nil {
			fmt.Fprintf(cmd.OutOrStdout(), "ClusterNetworkPolicy %s deleted\n", acnpTmp.Name)
		}
	}

	// Get all Services created by antrea-mc-controller and delete them.
	svcs := &corev1.ServiceList{}
	if err = k8sClient.List(ctx, svcs, &client.ListOptions{}); err != nil {
		return err
	}
	svcsCreatedByAntreaMC := []corev1.Service{}
	for _, svc := range svcs.Items {
		if svc.Annotations[AntreaMCServiceAnnotation] == "true" {
			svcsCreatedByAntreaMC = append(svcsCreatedByAntreaMC, svc)
		}
	}
	for _, svc := range svcsCreatedByAntreaMC {
		svcTmp := svc
		err := k8sClient.Delete(ctx, &svcTmp, &client.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if err == nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Service %s/%s deleted\n", svcTmp.Namespace, svcTmp.Name)
		}
	}
	return nil
}

func getAPIGroupResourcesWrapper(k8sClient kubernetes.Interface) ([]*restmapper.APIGroupResources, error) {
	return restmapper.GetAPIGroupResources(k8sClient.Discovery())
}
