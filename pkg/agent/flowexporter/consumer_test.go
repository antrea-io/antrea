package flowexporter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestConsumer_resolveAddress(t *testing.T) {
	ctx := context.Background()

	k8sClient := fake.NewSimpleClientset(
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "svc1",
				Namespace: "ns",
			},
			Spec: corev1.ServiceSpec{
				Type:       corev1.ServiceTypeClusterIP,
				ClusterIP:  "10.96.1.201",
				ClusterIPs: []string{"10.96.1.201"},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "svc2",
				Namespace: "ns",
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeClusterIP,
				// missing ClusterIP
			},
		},
	)

	testCases := []struct {
		name               string
		inputAddr          string
		expectedAddr       string
		expectedServerName string
		expectedErr        string
	}{
		{
			name:         "IP address",
			inputAddr:    "10.96.1.100:4739",
			expectedAddr: "10.96.1.100:4739",
		},
		{
			name:               "Service name",
			inputAddr:          "ns/svc1:4739",
			expectedAddr:       "10.96.1.201:4739",
			expectedServerName: "svc1.ns.svc",
		},
		{
			name:        "Service without ClusterIP",
			inputAddr:   "ns/svc2:4739",
			expectedErr: "ClusterIP is not available for Service",
		},
		{
			name:        "Missing Service",
			inputAddr:   "ns/svc3:4739",
			expectedErr: "failed to resolve Service",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			consumer := &Consumer{
				ConsumerConfig: &ConsumerConfig{
					address: tc.inputAddr,
				},
				k8sClient: k8sClient,
			}

			addr, name, err := consumer.resolveAddress(ctx)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedAddr, addr)
				assert.Equal(t, tc.expectedServerName, name)
			}
		})
	}
}
