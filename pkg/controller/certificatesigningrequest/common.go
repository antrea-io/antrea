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

package certificatesigningrequest

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"time"

	certificates "k8s.io/api/certificates/v1"
	sautil "k8s.io/apiserver/pkg/authentication/serviceaccount"
	certutil "k8s.io/client-go/util/cert"

	antreaapis "antrea.io/antrea/pkg/apis"
)

const (
	// Set resyncPeriod to 0 to disable resyncing.
	resyncPeriod time.Duration = 0
	// How long to wait before retrying the processing of a CertificateSigningRequest change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing a CertificateSigningRequest change.
	defaultWorkers = 2
)

var (
	errOrganizationNotAntrea    = fmt.Errorf("subject organization is not %s", antreaapis.AntreaOrganizationName)
	errDNSSANNotMatchCommonName = fmt.Errorf("DNS subjectAltNames do not match subject common name")
	errEmailSANNotAllowed       = fmt.Errorf("email subjectAltNames are not allowed")
	errIPSANNotAllowed          = fmt.Errorf("IP subjectAltNames are not allowed")
	errURISANNotAllowed         = fmt.Errorf("URI subjectAltNames are not allowed")
	errCommonNameRequired       = fmt.Errorf("subject common name is required")
	errExtraFieldsRequired      = fmt.Errorf("extra values must contain %q and %q", sautil.PodNameKey, sautil.PodUIDKey)
	errPodUIDMismatch           = fmt.Errorf("Pod UID does not match")
	errPodNotOnNode             = fmt.Errorf("Pod is not on requested Node")
	errUserUnauthorized         = fmt.Errorf("Unrecognized username")
)

// isCertificateRequestApproved returns true if a certificate request has the
// "Approved" condition and no "Denied" conditions; false otherwise.
func isCertificateRequestApproved(csr *certificates.CertificateSigningRequest) bool {
	approved, denied := getCertApprovalCondition(&csr.Status)
	return approved && !denied
}

func decodeCertificateRequest(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != certutil.CertificateRequestBlockType {
		err := fmt.Errorf("PEM block type must be %s", certutil.CertificateRequestBlockType)
		return nil, err
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

type transientError struct {
	error
}

func getCertApprovalCondition(status *certificates.CertificateSigningRequestStatus) (bool, bool) {
	var approved, denied bool
	for _, c := range status.Conditions {
		if c.Type == certificates.CertificateApproved {
			approved = true
		}
		if c.Type == certificates.CertificateDenied {
			denied = true
		}
	}
	return approved, denied
}

var keyUsageDict = map[certificates.KeyUsage]x509.KeyUsage{
	certificates.UsageSigning:           x509.KeyUsageDigitalSignature,
	certificates.UsageDigitalSignature:  x509.KeyUsageDigitalSignature,
	certificates.UsageContentCommitment: x509.KeyUsageContentCommitment,
	certificates.UsageKeyEncipherment:   x509.KeyUsageKeyEncipherment,
	certificates.UsageKeyAgreement:      x509.KeyUsageKeyAgreement,
	certificates.UsageDataEncipherment:  x509.KeyUsageDataEncipherment,
	certificates.UsageCertSign:          x509.KeyUsageCertSign,
	certificates.UsageCRLSign:           x509.KeyUsageCRLSign,
	certificates.UsageEncipherOnly:      x509.KeyUsageEncipherOnly,
	certificates.UsageDecipherOnly:      x509.KeyUsageDecipherOnly,
}

var extKeyUsageDict = map[certificates.KeyUsage]x509.ExtKeyUsage{
	certificates.UsageAny:             x509.ExtKeyUsageAny,
	certificates.UsageServerAuth:      x509.ExtKeyUsageServerAuth,
	certificates.UsageClientAuth:      x509.ExtKeyUsageClientAuth,
	certificates.UsageCodeSigning:     x509.ExtKeyUsageCodeSigning,
	certificates.UsageEmailProtection: x509.ExtKeyUsageEmailProtection,
	certificates.UsageSMIME:           x509.ExtKeyUsageEmailProtection,
	certificates.UsageIPsecEndSystem:  x509.ExtKeyUsageIPSECEndSystem,
	certificates.UsageIPsecTunnel:     x509.ExtKeyUsageIPSECTunnel,
	certificates.UsageIPsecUser:       x509.ExtKeyUsageIPSECUser,
	certificates.UsageTimestamping:    x509.ExtKeyUsageTimeStamping,
	certificates.UsageOCSPSigning:     x509.ExtKeyUsageOCSPSigning,
	certificates.UsageMicrosoftSGC:    x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	certificates.UsageNetscapeSGC:     x509.ExtKeyUsageNetscapeServerGatedCrypto,
}

// keyUsagesFromStrings will translate a slice of usage strings from the
// certificates API ("pkg/apis/certificates".KeyUsage) to x509.KeyUsage and
// x509.ExtKeyUsage types.
func keyUsagesFromStrings(usages []certificates.KeyUsage) (x509.KeyUsage, []x509.ExtKeyUsage, error) {
	var keyUsage x509.KeyUsage
	var unrecognized []certificates.KeyUsage
	extKeyUsages := make(map[x509.ExtKeyUsage]struct{})
	for _, usage := range usages {
		if val, ok := keyUsageDict[usage]; ok {
			keyUsage |= val
		} else if val, ok := extKeyUsageDict[usage]; ok {
			extKeyUsages[val] = struct{}{}
		} else {
			unrecognized = append(unrecognized, usage)
		}
	}

	var sorted sortedExtKeyUsage
	for eku := range extKeyUsages {
		sorted = append(sorted, eku)
	}
	sort.Sort(sorted)

	if len(unrecognized) > 0 {
		return 0, nil, fmt.Errorf("unrecognized usage values: %q", unrecognized)
	}

	return keyUsage, sorted, nil
}

type sortedExtKeyUsage []x509.ExtKeyUsage

func (s sortedExtKeyUsage) Len() int {
	return len(s)
}

func (s sortedExtKeyUsage) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s sortedExtKeyUsage) Less(i, j int) bool {
	return s[i] < s[j]
}
