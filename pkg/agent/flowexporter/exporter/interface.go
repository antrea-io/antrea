// Copyright 2025 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package exporter

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
)

type TLSConfig struct {
	ServerName    string
	CAData        []byte
	CertData      []byte
	KeyData       []byte
	MinTLSVersion string
}

// AsStdConfig converts the TLSConfig to the standard tls.Config.
func (c *TLSConfig) AsStdConfig() (*tls.Config, error) {
	var minTLSVersion uint16 = tls.VersionTLS12
	switch c.MinTLSVersion {
	case "VersionTLS12":
		minTLSVersion = tls.VersionTLS12
	case "VersionTLS13":
		minTLSVersion = tls.VersionTLS13
	}

	tlsConfig := &tls.Config{
		ServerName: c.ServerName,
		MinVersion: minTLSVersion,
	}
	// Use system roots if c.CAData == nil.
	if c.CAData != nil {
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM(c.CAData)
		if !ok {
			return nil, fmt.Errorf("failed to parse root certificate")
		}
		tlsConfig.RootCAs = roots
	}
	// Don't use a client certificate if c.CertData == nil.
	if c.CertData != nil {
		cert, err := tls.X509KeyPair(c.CertData, c.KeyData)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig, nil
}

// Implementations of this interface don't provide any guarantees regarding thread-safety.
type Interface interface {
	ConnectToCollector(addr string, tlsConfig *TLSConfig) error
	Export(conn *connection.Connection) error
	CloseConnToCollector()
}
