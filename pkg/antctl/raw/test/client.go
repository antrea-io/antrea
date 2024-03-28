// Copyright 2024 Antrea Authors.
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

package test

import (
	"bytes"
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/remotecommand"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Client struct {
	clientSet   kubernetes.Interface
	config      *rest.Config
	clusterName string
}

type ExecResult struct {
	Stdout bytes.Buffer
	Stderr bytes.Buffer
}

func NewClient() (*Client, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()

	nonInteractiveClient := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{})

	config, err := nonInteractiveClient.ClientConfig()
	if err != nil {
		return nil, err
	}

	rawConfig, err := nonInteractiveClient.RawConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	contextName := rawConfig.CurrentContext

	clusterName := ""
	if context, ok := rawConfig.Contexts[contextName]; ok {
		clusterName = context.Cluster
	}

	return &Client{
		clientSet:   clientset,
		config:      config,
		clusterName: clusterName,
	}, nil
}

func (c *Client) ClusterName() (name string) {
	return c.clusterName
}

func (c *Client) CreateService(ctx context.Context, namespace string, service *corev1.Service, opts metav1.CreateOptions) (*corev1.Service, error) {
	return c.clientSet.CoreV1().Services(namespace).Create(ctx, service, opts)
}

func (c *Client) CreateDeployment(ctx context.Context, namespace string, deployment *appsv1.Deployment, opts metav1.CreateOptions) (*appsv1.Deployment, error) {
	return c.clientSet.AppsV1().Deployments(namespace).Create(ctx, deployment, opts)
}

func (c *Client) GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error) {
	return c.clientSet.AppsV1().Deployments(namespace).Get(ctx, name, opts)
}

func (c *Client) DeploymentIsReady(ctx context.Context, namespace, deploymentName string) (bool, error) {
	deployment, err := c.GetDeployment(ctx, namespace, deploymentName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	if deployment.Generation <= deployment.Status.ObservedGeneration {
		for _, cond := range deployment.Status.Conditions {
			if cond.Type == appsv1.DeploymentProgressing && cond.Reason == "ProgressDeadlineExceeded" {
				return false, fmt.Errorf("deployment %q exceeded its progress deadline", deployment.Name)
			}
		}
		if deployment.Spec.Replicas != nil && deployment.Status.UpdatedReplicas < *deployment.Spec.Replicas {
			return false, nil
		}
		if deployment.Status.Replicas > deployment.Status.UpdatedReplicas {
			return false, nil
		}
		if deployment.Status.AvailableReplicas < deployment.Status.UpdatedReplicas {
			return false, nil
		}
		return true, nil
	}
	return false, nil
}

func (c *Client) CreateNamespace(ctx context.Context, namespace string, opts metav1.CreateOptions) (*corev1.Namespace, error) {
	return c.clientSet.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}, opts)
}

func (c *Client) GetNamespace(ctx context.Context, namespace string, options metav1.GetOptions) (*corev1.Namespace, error) {
	return c.clientSet.CoreV1().Namespaces().Get(ctx, namespace, options)
}

func (c *Client) DeleteNamespace(ctx context.Context, namespace string, opts metav1.DeleteOptions) error {
	return c.clientSet.CoreV1().Namespaces().Delete(ctx, namespace, opts)
}

func (c *Client) ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error) {
	return c.clientSet.CoreV1().Pods(namespace).List(ctx, options)
}

func (c *Client) ExecInPod(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, error) {
	req := c.clientSet.CoreV1().RESTClient().Post().Resource("pods").Name(pod).Namespace(namespace).SubResource("exec")

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return bytes.Buffer{}, fmt.Errorf("error adding to scheme: %w", err)
	}

	parameterCodec := runtime.NewParameterCodec(scheme)

	req.VersionedParams(&corev1.PodExecOptions{
		Command:   command,
		Container: container,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}, parameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(c.config, "POST", req.URL())
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("error while creating executor: %w", err)
	}

	result := &ExecResult{}

	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: &result.Stdout,
		Stderr: &result.Stderr,
		Tty:    false,
	})
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("error in stream: %w", err)
	}

	if errString := result.Stderr.String(); errString != "" {
		return bytes.Buffer{}, fmt.Errorf("command failed: %s", errString)
	}

	return result.Stdout, nil
}

func (c *Client) GetDaemonSet(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.DaemonSet, error) {
	return c.clientSet.AppsV1().DaemonSets(namespace).Get(ctx, name, opts)
}
