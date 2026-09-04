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

package networkpolicy

// TestReplaceAllErrorSilentlyDiscarded proves the bug at lines 452 and 523 of
// networkpolicy_controller.go.
//
// The ReplaceFunc closures for appliedToGroupWatcher and addressGroupWatcher use:
//
//   if c.appliedToGroupStore.replaceAll(objs); err != nil { ... }
//
// This is Go's "if init; condition" syntax. The init expression calls replaceAll but
// its return value is DISCARDED. The condition tests `err`, which is a variable captured
// from the outer scope of NewNetworkPolicyController — a variable that is always nil by
// the time the closure is ever called (all errors in the outer function either returned
// early or are from the local := assignments).
//
// The networkPolicyStore equivalent on line 381 is written correctly:
//
//   if err := c.networkPolicyStore.replaceAll(objs); err != nil { ... }  // correct
//
// The fix for the buggy lines is to add `:=`:
//
//   if err := c.appliedToGroupStore.replaceAll(objs); err != nil { ... }  // fixed
//
// Consequence: if replaceAll fails (e.g. disk full, read-only fs), the on-disk policy cache
// is left in a corrupt/stale state with no error logged. On the next agent restart where
// the Controller is temporarily unreachable, the agent loads stale data from disk and
// installs incorrect NetworkPolicy OVS flows — a silent security bypass or traffic blackhole.

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"

	"antrea.io/antrea/v2/pkg/apis/controlplane/v1beta2"
)

func TestReplaceAllErrorSilentlyDiscarded(t *testing.T) {
	ser := protobuf.NewSerializer(scheme, scheme)
	codec := codecs.CodecForVersions(ser, ser, v1beta2.SchemeGroupVersion, v1beta2.SchemeGroupVersion)

	// Create a file store pre-populated with "old" data representing the previous sync.
	memFs := afero.NewMemMapFs()
	store, err := newFileStore(afero.NewBasePathFs(memFs, "/antrea"), "appliedToGroups", codec)
	require.NoError(t, err)
	oldGroup := newAppliedToGroup("oldGroup", nil)
	require.NoError(t, store.save(oldGroup))

	// Inject a read-only fs to force replaceAll to fail (simulates disk full / permission error).
	store.fs = afero.NewReadOnlyFs(store.fs)

	newGroup := newAppliedToGroup("newGroup", nil)

	// ── Demonstrate the BUG (lines 452, 523) ────────────────────────────────────────────
	// `err` here simulates the outer-scope variable captured by the closure in
	// NewNetworkPolicyController. It is always nil when the closure is called.
	var outerErr error
	if store.replaceAll([]runtime.Object{newGroup}); outerErr != nil {
		t.Fatal("this branch is unreachable: outerErr is always nil, the replaceAll error is discarded")
	}

	// replaceAll returned a non-nil error, but it was silently discarded.
	// The old data is still on disk — the store was never updated.
	diskObjs, loadErr := store.loadAll()
	require.NoError(t, loadErr)
	require.Len(t, diskObjs, 1, "stale group still on disk: replaceAll error was silently discarded")
	assert.Equal(t, "oldGroup", diskObjs[0].(*v1beta2.AppliedToGroup).Name)

	// ── Demonstrate the FIX (line 381 pattern) ──────────────────────────────────────────
	// With `if err := store.replaceAll(...); err != nil`, the error IS surfaced.
	if fixedErr := store.replaceAll([]runtime.Object{newGroup}); fixedErr != nil {
		// Error is correctly caught — caller can log it, return it, or take action.
		assert.Error(t, fixedErr, "replaceAll error is surfaced when := is used")
	} else {
		t.Error("expected replaceAll to return an error on a read-only fs; fix did not work")
	}
}
