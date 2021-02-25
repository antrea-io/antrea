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

package certificate

import (
	"bytes"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/wait"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	fakeaggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"
)

const (
	fakeTLSCert = `-----BEGIN CERTIFICATE-----
MIICBDCCAW2gAwIBAgIJAPgVBh+4xbGoMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAMMEHdlYmhvb2tfdGVzdHNfY2EwIBcNMTcwNzI4MjMxNTI4WhgPMjI5MTA1MTMy
MzE1MjhaMB8xHTAbBgNVBAMMFHdlYmhvb2tfdGVzdHNfY2xpZW50MIGfMA0GCSqG
SIb3DQEBAQUAA4GNADCBiQKBgQDkGXXSm6Yun5o3Jlmx45rItcQ2pmnoDk4eZfl0
rmPa674s2pfYo3KywkXQ1Fp3BC8GUgzPLSfJ8xXya9Lg1Wo8sHrDln0iRg5HXxGu
uFNhRBvj2S0sIff0ZG/IatB9I6WXVOUYuQj6+A0CdULNj1vBqH9+7uWbLZ6lrD4b
a44x/wIDAQABo0owSDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DAdBgNVHSUEFjAU
BggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0RBAgwBocEfwAAATANBgkqhkiG9w0B
AQsFAAOBgQCpN27uh/LjUVCaBK7Noko25iih/JSSoWzlvc8CaipvSPofNWyGx3Vu
OdcSwNGYX/pp4ZoAzFij/Y5u0vKTVLkWXATeTMVmlPvhmpYjj9gPkCSY6j/SiKlY
kGy0xr+0M5UQkMBcfIh9oAp9um1fZHVWAJAGP/ikZgkcUey0LmBn8w==
-----END CERTIFICATE-----`
	fakeTLSKey = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDkGXXSm6Yun5o3Jlmx45rItcQ2pmnoDk4eZfl0rmPa674s2pfY
o3KywkXQ1Fp3BC8GUgzPLSfJ8xXya9Lg1Wo8sHrDln0iRg5HXxGuuFNhRBvj2S0s
Iff0ZG/IatB9I6WXVOUYuQj6+A0CdULNj1vBqH9+7uWbLZ6lrD4ba44x/wIDAQAB
AoGAZbWwowvCq1GBq4vPPRI3h739Uz0bRl1ymf1woYXNguXRtCB4yyH+2BTmmrrF
6AIWkePuUEdbUaKyK5nGu3iOWM+/i6NP3kopQANtbAYJ2ray3kwvFlhqyn1bxX4n
gl/Cbdw1If4zrDrB66y8mYDsjzK7n/gFaDNcY4GArjvOXKkCQQD9Lgv+WD73y4RP
yS+cRarlEeLLWVsX/pg2oEBLM50jsdUnrLSW071MjBgP37oOXzqynF9SoDbP2Y5C
x+aGux9LAkEA5qPlQPv0cv8Wc3qTI+LixZ/86PPHKWnOnwaHm3b9vQjZAkuVQg3n
Wgg9YDmPM87t3UFH7ZbDihUreUxwr9ZjnQJAZ9Z95shMsxbOYmbSVxafu6m1Sc+R
M+sghK7/D5jQpzYlhUspGf8n0YBX0hLhXUmjamQGGH5LXL4Owcb4/mM6twJAEVio
SF/qva9jv+GrKVrKFXT374lOJFY53Qn/rvifEtWUhLCslCA5kzLlctRBafMZPrfH
Mh5RrJP1BhVysDbenQJASGcc+DiF7rB6K++ZGyC11E2AP29DcZ0pgPESSV7npOGg
+NqPRZNVCSZOiVmNuejZqmwKhZNGZnBFx1Y+ChAAgw==
-----END RSA PRIVATE KEY-----`
	fakeCACert = `-----BEGIN CERTIFICATE-----
MIICBDCCAW2gAwIBAgIJAPgVBh+4xbGoMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAMMEHdlYmhvb2tfdGVzdHNfY2EwIBcNMTcwNzI4MjMxNTI4WhgPMjI5MTA1MTMy
MzE1MjhaMB8xHTAbBgNVBAMMFHdlYmhvb2tfdGVzdHNfY2xpZW50MIGfMA0GCSqG
SIb3DQEBAQUAA4GNADCBiQKBgQDkGXXSm6Yun5o3Jlmx45rItcQ2pmnoDk4eZfl0
rmPa674s2pfYo3KywkXQ1Fp3BC8GUgzPLSfJ8xXya9Lg1Wo8sHrDln0iRg5HXxGu
uFNhRBvj2S0sIff0ZG/IatB9I6WXVOUYuQj6+A0CdULNj1vBqH9+7uWbLZ6lrD4b
a44x/wIDAQABo0owSDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DAdBgNVHSUEFjAU
BggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0RBAgwBocEfwAAATANBgkqhkiG9w0B
AQsFAAOBgQCpN27uh/LjUVCaBK7Noko25iih/JSSoWzlvc8CaipvSPofNWyGx3Vu
OdcSwNGYX/pp4ZoAzFij/Y5u0vKTVLkWXATeTMVmlPvhmpYjj9gPkCSY6j/SiKlY
kGy0xr+0M5UQkMBcfIh9oAp9um1fZHVWAJAGP/ikZgkcUey0LmBn8w==
-----END CERTIFICATE-----`
)

func TestApplyServerCert(t *testing.T) {
	tests := []struct {
		name              string
		selfSignedCert    bool
		tlsCert           []byte
		tlsKey            []byte
		caCert            []byte
		wantErr           bool
		wantCertKey       bool
		wantGeneratedCert bool
		wantCACert        []byte
		testRotate        bool
	}{
		{
			name:              "self-signed",
			selfSignedCert:    true,
			tlsCert:           nil,
			tlsKey:            nil,
			caCert:            nil,
			wantErr:           false,
			wantCertKey:       false,
			wantGeneratedCert: true,
			wantCACert:        nil,
			testRotate:        false,
		},
		{
			name:              "user-provided",
			selfSignedCert:    false,
			tlsCert:           []byte(fakeTLSCert),
			tlsKey:            []byte(fakeTLSKey),
			caCert:            []byte(fakeCACert),
			wantErr:           false,
			wantCertKey:       true,
			wantGeneratedCert: false,
			wantCACert:        []byte(fakeCACert),
			testRotate:        false,
		},
		{
			name:           "user-provided-missing-tls-crt",
			selfSignedCert: false,
			tlsCert:        nil,
			tlsKey:         []byte(fakeTLSKey),
			caCert:         []byte(fakeCACert),
			wantErr:        true,
			testRotate:     false,
		},
		{
			name:           "user-provided-missing-tls-key",
			selfSignedCert: false,
			tlsCert:        []byte(fakeTLSCert),
			tlsKey:         nil,
			caCert:         []byte(fakeCACert),
			wantErr:        true,
			testRotate:     false,
		},
		{
			name:           "user-provided-missing-ca-crt",
			selfSignedCert: false,
			tlsCert:        []byte(fakeTLSCert),
			tlsKey:         []byte(fakeTLSKey),
			caCert:         nil,
			wantErr:        true,
			testRotate:     false,
		},
		{
			name:              "self-signed-rotate",
			selfSignedCert:    true,
			tlsCert:           nil,
			tlsKey:            nil,
			caCert:            nil,
			wantErr:           false,
			wantCertKey:       false,
			wantGeneratedCert: true,
			wantCACert:        nil,
			testRotate:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			certDir, err = ioutil.TempDir("", "antrea-tls-test")
			if err != nil {
				t.Fatalf("Unable to create temporary directory: %v", err)
			}
			defer os.RemoveAll(certDir)
			selfSignedCertDir, err = ioutil.TempDir("", "antrea-self-signed")
			if err != nil {
				t.Fatalf("Unable to create temporary directory: %v", err)
			}
			defer os.RemoveAll(selfSignedCertDir)
			certReadyTimeout = 100 * time.Millisecond
			secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
			if tt.tlsCert != nil {
				certutil.WriteCert(path.Join(certDir, TLSCertFile), tt.tlsCert)
			}
			if tt.tlsKey != nil {
				keyutil.WriteKey(path.Join(certDir, TLSKeyFile), tt.tlsKey)
			}
			if tt.caCert != nil {
				certutil.WriteCert(path.Join(certDir, CACertFile), tt.caCert)
			}

			if tt.testRotate {
				maxRotateDuration = 2 * time.Second
			}

			clientset := fakeclientset.NewSimpleClientset()
			aggregatorClientset := fakeaggregatorclientset.NewSimpleClientset()
			got, err := ApplyServerCert(tt.selfSignedCert, clientset, aggregatorClientset, secureServing)

			if err != nil || tt.wantErr {
				if (err != nil) != tt.wantErr {
					t.Errorf("ApplyServerCert() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if tt.selfSignedCert && tt.testRotate {
				oldCertKeyContent := got.getCertificate()
				err := wait.Poll(time.Second, 8*time.Second, func() (bool, error) {
					newCertKeyContent := got.getCertificate()
					equal := bytes.Equal(oldCertKeyContent, newCertKeyContent)
					return !equal, nil
				})

				assert.Nil(t, err, "CA cert not updated")
			}

			if tt.wantCertKey {
				assert.Equal(t, genericoptions.CertKey{CertFile: certDir + "/tls.crt", KeyFile: certDir + "/tls.key"}, secureServing.ServerCert.CertKey, "CertKey doesn't match")
			}
			if tt.wantGeneratedCert {
				assert.Equal(t, genericoptions.CertKey{CertFile: selfSignedCertDir + "/antrea-controller.crt", KeyFile: selfSignedCertDir + "/antrea-controller.key"}, secureServing.ServerCert.CertKey, "SelfSigned certs not generated")
			} else {
				assert.NotEqual(t, genericoptions.CertKey{CertFile: selfSignedCertDir + "/antrea-controller.crt", KeyFile: selfSignedCertDir + "/antrea-controller.key"}, secureServing.ServerCert.CertKey, "SelfSigned certs generated erroneously")
			}
			if tt.wantCACert != nil {
				assert.Equal(t, tt.wantCACert, got.caContentProvider.CurrentCABundleContent(), "CA cert doesn't match")
			} else {
				assert.NotEmpty(t, got.caContentProvider.CurrentCABundleContent(), "CA cert is empty")
			}
		})
	}
}
