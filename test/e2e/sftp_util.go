// Copyright 2024 Antrea Authors
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

package e2e

import (
	"context"
	"fmt"

	"golang.org/x/crypto/ssh"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	sftptesting "antrea.io/antrea/pkg/util/sftp/testing"
)

var sftpLabels = map[string]string{"app": "sftp"}

const (
	sftpUser      = "foo"
	sftpPassword  = "pass"
	sftpUploadDir = "upload"
)

func genSFTPService(nodePort int32) *v1.Service {
	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "sftp",
			Labels: sftpLabels,
		},
		Spec: v1.ServiceSpec{
			Type:     v1.ServiceTypeNodePort,
			Selector: sftpLabels,
			Ports: []v1.ServicePort{
				{
					Port:       22,
					TargetPort: intstr.FromInt32(22),
					NodePort:   nodePort,
				},
			},
		},
	}
}

func genSSHKeysSecret(ed25519Key, rsaKey []byte) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ssh-keys",
		},
		Immutable: ptr.To(true),
		Data: map[string][]byte{
			"ed25519": ed25519Key,
			"rsa":     rsaKey,
		},
	}
}

func genSFTPDeployment() *appsv1.Deployment {
	replicas := int32(1)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "sftp",
			Labels: sftpLabels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: sftpLabels,
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "sftp",
					Labels: sftpLabels,
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:            "sftp",
							Image:           "ghcr.io/atmoz/sftp/debian:latest",
							ImagePullPolicy: v1.PullIfNotPresent,
							Args:            []string{fmt.Sprintf("%s:%s:::%s", sftpUser, sftpPassword, sftpUploadDir)},
							ReadinessProbe: &v1.Probe{
								ProbeHandler: v1.ProbeHandler{
									TCPSocket: &v1.TCPSocketAction{
										Port: intstr.FromInt32(int32(22)),
									},
								},
								PeriodSeconds: 3,
							},
							VolumeMounts: []v1.VolumeMount{
								{
									Name:      "ssh-keys",
									ReadOnly:  true,
									MountPath: "/etc/ssh/ssh_host_ed25519_key",
									SubPath:   "ed25519",
								},
								{
									Name:      "ssh-keys",
									ReadOnly:  true,
									MountPath: "/etc/ssh/ssh_host_rsa_key",
									SubPath:   "rsa",
								},
							},
						},
					},
					Volumes: []v1.Volume{
						{
							Name: "ssh-keys",
							VolumeSource: v1.VolumeSource{
								Secret: &v1.SecretVolumeSource{
									SecretName:  "ssh-keys",
									DefaultMode: ptr.To[int32](0400),
								},
							},
						},
					},
				},
			},
		},
	}
}

func (data *TestData) deploySFTPServer(ctx context.Context, nodePort int32) (*appsv1.Deployment, *v1.Service, []ssh.PublicKey, error) {
	ed25519PubKey, ed25519PrivateKey, err := sftptesting.GenerateEd25519Key()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}
	rsaPubKey, rsaPrivateKey, err := sftptesting.GenerateRSAKey(4096)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	pubKeys := []ssh.PublicKey{ed25519PubKey, rsaPubKey}

	_, err = data.clientset.CoreV1().Secrets(data.testNamespace).Create(ctx, genSSHKeysSecret(ed25519PrivateKey, rsaPrivateKey), metav1.CreateOptions{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create Secret for SSH private keys: %w", err)
	}
	deployment, err := data.clientset.AppsV1().Deployments(data.testNamespace).Create(ctx, genSFTPDeployment(), metav1.CreateOptions{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create SFTP Deployment: %w", err)
	}
	svc, err := data.clientset.CoreV1().Services(data.testNamespace).Create(ctx, genSFTPService(nodePort), metav1.CreateOptions{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create SFTP Service: %w", err)
	}

	return deployment, svc, pubKeys, nil
}
