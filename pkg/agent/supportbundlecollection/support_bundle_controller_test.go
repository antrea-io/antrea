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

package supportbundlecollection

import (
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/klog/v2"
	"k8s.io/utils/exec"

	agentquerier "antrea.io/antrea/pkg/agent/querier"
	"antrea.io/antrea/pkg/apis/controlplane"
	cpv1b2 "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/support"
	"antrea.io/antrea/pkg/util/sftp"
	sftptesting "antrea.io/antrea/pkg/util/sftp/testing"
)

type fakeController struct {
	*SupportBundleController
	mockController *gomock.Controller
}

type antreaClientGetter struct {
	clientset versioned.Interface
}

func (g *antreaClientGetter) GetAntreaClient() (versioned.Interface, error) {
	return g.clientset, nil
}

func newFakeController(t *testing.T) (*fakeController, *fakeversioned.Clientset) {
	controller := gomock.NewController(t)
	clientset := &fakeversioned.Clientset{}
	supportBundleController := NewSupportBundleController("vm1", controlplane.SupportBundleCollectionNodeTypeExternalNode, "vm-ns", &antreaClientGetter{clientset}, nil,
		nil, nil, true, true)
	return &fakeController{
		SupportBundleController: supportBundleController,
		mockController:          controller,
	}, clientset
}

func TestSupportBundleCollectionAdd(t *testing.T) {
	uploadErr := fmt.Errorf("upload failed")
	generateHostKey := func(t *testing.T) ssh.PublicKey {
		publicKey, _, err := sftptesting.GenerateEd25519Key()
		require.NoError(t, err)
		return publicKey
	}
	hostKey1 := generateHostKey(t)
	hostKey2 := generateHostKey(t)

	testcases := []struct {
		name                    string
		supportBundleCollection *cpv1b2.SupportBundleCollection
		agentDumper             *mockAgentDumper
		uploader                sftp.Uploader
		expectedSyncErr         string
	}{
		{
			name:                    "Add SupportBundleCollection",
			supportBundleCollection: generateSupportbundleCollection("supportBundle1", "sftp://10.220.175.92:22/root/supportbundle", nil),
			agentDumper:             &mockAgentDumper{},
			uploader:                &testUploader{},
		},
		{
			name:                    "Add SupportBundleCollection without url prefix",
			supportBundleCollection: generateSupportbundleCollection("supportBundle2", "10.220.175.92:22/root/supportbundle", nil),
			agentDumper:             &mockAgentDumper{},
			uploader:                &testUploader{},
		},
		{
			name:                    "Add SupportBundleCollection with unsupported url prefix",
			supportBundleCollection: generateSupportbundleCollection("supportBundle3", "https://10.220.175.92:22/root/supportbundle", nil),
			agentDumper:             &mockAgentDumper{},
			uploader: &testUploader{
				err: uploadErr,
			},
			expectedSyncErr: uploadErr.Error(),
		},
		{
			name:                    "Add SupportBundleCollection with retry logics",
			supportBundleCollection: generateSupportbundleCollection("supportBundle4", "10.220.175.92:22/root/supportbundle", nil),
			agentDumper:             &mockAgentDumper{},
			uploader: &testUploader{
				err: uploadErr,
			},
			expectedSyncErr: uploadErr.Error(),
		},
		{
			name:                    "SupportBundleCollection failed to dump log",
			supportBundleCollection: generateSupportbundleCollection("supportBundle5", "sftp://10.220.175.92:22/root/supportbundle", nil),
			agentDumper:             &mockAgentDumper{dumpLogErr: fmt.Errorf("failed to dump log")},
			uploader:                &testUploader{},
			expectedSyncErr:         "failed to generate support bundle: failed to dump log",
		},
		{
			name:                    "SupportBundleCollection failed to dump flows",
			supportBundleCollection: generateSupportbundleCollection("supportBundle6", "sftp://10.220.175.92:22/root/supportbundle", nil),
			agentDumper:             &mockAgentDumper{dumpFlowsErr: fmt.Errorf("failed to dump flows")},
			uploader:                &testUploader{},
			expectedSyncErr:         "failed to generate support bundle: failed to dump flows",
		},
		{
			name:                    "SupportBundleCollection failed to dump host network info",
			supportBundleCollection: generateSupportbundleCollection("supportBundle7", "sftp://10.220.175.92:22/root/supportbundle", nil),
			agentDumper:             &mockAgentDumper{dumpHostNetworkInfoErr: fmt.Errorf("failed to dump host network info")},
			uploader:                &testUploader{},
			expectedSyncErr:         "failed to generate support bundle: failed to dump host network info",
		},
		{
			name:                    "SupportBundleCollection failed to dump agent info",
			supportBundleCollection: generateSupportbundleCollection("supportBundle8", "sftp://10.220.175.92:22/root/supportbundle", nil),
			agentDumper:             &mockAgentDumper{dumpAgentInfoErr: fmt.Errorf("failed to dump agent info")},
			uploader:                &testUploader{},
			expectedSyncErr:         "failed to generate support bundle: failed to dump agent info",
		},
		{
			name:                    "SupportBundleCollection failed to dump network policy resources",
			supportBundleCollection: generateSupportbundleCollection("supportBundle9", "sftp://10.220.175.92:22/root/supportbundle", nil),
			agentDumper:             &mockAgentDumper{dumpNetworkPolicyResourcesErr: fmt.Errorf("failed to dump network policy resources")},
			uploader:                &testUploader{},
			expectedSyncErr:         "failed to generate support bundle: failed to dump network policy resources",
		},
		{
			name:                    "SupportBundleCollection failed to dump heap Pprof",
			supportBundleCollection: generateSupportbundleCollection("supportBundle10", "sftp://10.220.175.92:22/root/supportbundle", nil),
			agentDumper:             &mockAgentDumper{dumpHeapPprofErr: fmt.Errorf("failed to dump heap Pprof")},
			uploader:                &testUploader{},
			expectedSyncErr:         "failed to generate support bundle: failed to dump heap Pprof",
		},
		{
			name:                    "SupportBundleCollection failed to dump OVS ports",
			supportBundleCollection: generateSupportbundleCollection("supportBundle11", "sftp://10.220.175.92:22/root/supportbundle", nil),
			agentDumper:             &mockAgentDumper{dumpOVSPortsErr: fmt.Errorf("failed to dump OVS ports")},
			uploader:                &testUploader{},
			expectedSyncErr:         "failed to generate support bundle: failed to dump OVS ports",
		},
		{
			name:                    "SupportBundleCollection failed to dump goroutine Pprof",
			supportBundleCollection: generateSupportbundleCollection("supportBundle12", "sftp://10.220.175.92:22/root/supportbundle", nil),
			agentDumper:             &mockAgentDumper{dumpGoroutinePprofErr: fmt.Errorf("failed to dump goroutine Pprof")},
			uploader:                &testUploader{},
			expectedSyncErr:         "failed to generate support bundle: failed to dump goroutine Pprof",
		},
		{
			name:                    "SupportBundleCollection failed to dump groups",
			supportBundleCollection: generateSupportbundleCollection("supportBundle13", "sftp://10.220.175.92:22/root/supportbundle", nil),
			agentDumper:             &mockAgentDumper{dumpGroupsErr: fmt.Errorf("failed to dump groups")},
			uploader:                &testUploader{},
			expectedSyncErr:         "failed to generate support bundle: failed to dump groups",
		},
		{
			name:                    "Add SupportBundleCollection with host key",
			supportBundleCollection: generateSupportbundleCollection("supportBundle13", "sftp://10.220.175.92:22/root/supportbundle", hostKey1.Marshal()),
			agentDumper:             &mockAgentDumper{},
			uploader: &testUploader{
				hostKey: hostKey1,
			},
		},
		{
			name:                    "Add SupportBundleCollection with host key mismatch",
			supportBundleCollection: generateSupportbundleCollection("supportBundle14", "sftp://10.220.175.92:22/root/supportbundle", hostKey1.Marshal()),
			agentDumper:             &mockAgentDumper{},
			uploader: &testUploader{
				hostKey: hostKey2,
			},
			expectedSyncErr: "failed to generate support bundle: invalid host key: ssh: host key mismatch",
		},
		{
			name:                    "Add SupportBundleCollection with invalid host key",
			supportBundleCollection: generateSupportbundleCollection("supportBundle15", "sftp://10.220.175.92:22/root/supportbundle", []byte("abc")),
			agentDumper:             &mockAgentDumper{},
			uploader: &testUploader{
				hostKey: hostKey1,
			},
			expectedSyncErr: "failed to generate support bundle: failed to generate SSH client config: invalid host public key",
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			newAgentDumper = func(fs afero.Fs, executor exec.Interface, ovsCtlClient ovsctl.OVSCtlClient, aq agentquerier.AgentQuerier, npq querier.AgentNetworkPolicyInfoQuerier, since string, v4Enabled, v6Enabled bool) support.AgentDumper {
				return tt.agentDumper
			}
			defer func() {
				newAgentDumper = support.NewAgentDumper
			}()
			controller, clientset := newFakeController(t)
			controller.sftpUploader = tt.uploader
			var bundleStatus *cpv1b2.SupportBundleCollectionStatus
			clientset.AddReactor("update", "supportbundlecollections/status", k8stesting.ReactionFunc(func(action k8stesting.Action) (bool, runtime.Object, error) {
				bundleStatus = action.(k8stesting.UpdateAction).GetObject().(*cpv1b2.SupportBundleCollectionStatus)

				return false, bundleStatus, nil
			}))
			controller.addSupportBundleCollection(tt.supportBundleCollection)
			err := controller.syncSupportBundleCollection(tt.supportBundleCollection.Name)
			if tt.expectedSyncErr == "" {
				assert.NoError(t, err)
				assert.True(t, bundleStatus.Nodes[0].Completed)
			} else {
				assert.ErrorContains(t, err, tt.expectedSyncErr)
				assert.False(t, bundleStatus.Nodes[0].Completed)
			}
		})
	}
}

func TestSupportBundleCollectionDelete(t *testing.T) {
	controller, _ := newFakeController(t)
	deletedBundle := generateSupportbundleCollection("deletedBundle", "sftp://10.220.175.92/root/supportbundle", nil)
	controller.addSupportBundleCollection(deletedBundle)
	controller.deleteSupportBundleCollection(deletedBundle)
	assert.NoError(t, controller.syncSupportBundleCollection("deletedBundle"))
}

type testUploader struct {
	err     error
	hostKey ssh.PublicKey
}

func (uploader *testUploader) Upload(address string, path string, config *ssh.ClientConfig, tarGzFile io.Reader) error {
	klog.InfoS("Called test uploader", "err", uploader.err)
	if uploader.err != nil {
		return uploader.err
	}
	if _, err := sftp.ParseSFTPUploadUrl(address); err != nil {
		return err
	}
	if uploader.hostKey != nil {
		if config.HostKeyAlgorithms != nil && !slices.Equal(config.HostKeyAlgorithms, []string{uploader.hostKey.Type()}) {
			return fmt.Errorf("unsupported host key algorithm")
		}
		if err := config.HostKeyCallback("", nil, uploader.hostKey); err != nil {
			return fmt.Errorf("invalid host key: %w", err)
		}
	}
	return nil
}

func generateSupportbundleCollection(name string, url string, hostPublicKey []byte) *cpv1b2.SupportBundleCollection {
	return &cpv1b2.SupportBundleCollection{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},

		FileServer: cpv1b2.BundleFileServer{
			URL:           url,
			HostPublicKey: hostPublicKey,
		},
		Authentication: cpv1b2.BundleServerAuthConfiguration{
			BasicAuthentication: &cpv1b2.BasicAuthentication{
				Username: "AAA",
				Password: "BBBCCC",
			},
		},
	}
}

type mockAgentDumper struct {
	dumpLogErr                    error
	dumpFlowsErr                  error
	dumpGroupsErr                 error
	dumpHostNetworkInfoErr        error
	dumpAgentInfoErr              error
	dumpNetworkPolicyResourcesErr error
	dumpHeapPprofErr              error
	dumpGoroutinePprofErr         error
	dumpOVSPortsErr               error
	dumpMemberlistErr             error
}

func (d *mockAgentDumper) DumpLog(basedir string) error {
	return d.dumpLogErr
}

func (d *mockAgentDumper) DumpFlows(basedir string) error {
	return d.dumpFlowsErr
}

func (d *mockAgentDumper) DumpGroups(basedir string) error {
	return d.dumpGroupsErr
}

func (d *mockAgentDumper) DumpHostNetworkInfo(basedir string) error {
	return d.dumpHostNetworkInfoErr
}

func (d *mockAgentDumper) DumpAgentInfo(basedir string) error {
	return d.dumpAgentInfoErr
}

func (d *mockAgentDumper) DumpNetworkPolicyResources(basedir string) error {
	return d.dumpNetworkPolicyResourcesErr
}

func (d *mockAgentDumper) DumpHeapPprof(basedir string) error {
	return d.dumpHeapPprofErr
}

func (d *mockAgentDumper) DumpGoroutinePprof(basedir string) error {
	return d.dumpGoroutinePprofErr
}

func (d *mockAgentDumper) DumpOVSPorts(basedir string) error {
	return d.dumpOVSPortsErr
}

func (d *mockAgentDumper) DumpMemberlist(basedir string) error {
	return d.dumpMemberlistErr
}
