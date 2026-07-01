// Copyright 2026 Antrea Authors
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

package ovsconfig

import (
	"errors"
	"fmt"

	"github.com/ovn-kubernetes/libovsdb/ovsdb"
	"k8s.io/klog/v2"
)

// convertOVSDBErrors returns transaction-level and operation-level errors.
func convertOVSDBErrors(opErrs []ovsdb.OperationError, txErr error) error {
	var errs []error
	if len(opErrs) > 0 {
		for _, opErr := range opErrs {
			logOVSDBOperationError(opErr)
			errs = append(errs, opErr)
		}
	}

	if txErr != nil {
		if len(errs) > 0 {
			return fmt.Errorf("OVSDB transaction failed: %w, with %d operation errors: %w", txErr, len(errs), errors.Join(errs...))
		}
		return fmt.Errorf("OVSDB transaction failed: %w", txErr)
	}

	if len(errs) > 0 {
		return fmt.Errorf("OVSDB transaction returned %d operation errors: %w", len(errs), errors.Join(errs...))
	}

	return nil
}

func logOVSDBOperationError(opErr ovsdb.OperationError) {
	switch err := opErr.(type) {
	case *ovsdb.TimedOut:
		klog.V(4).InfoS("OVSDB wait operation timed out", "error", err)
	case *ovsdb.ConstraintViolation:
		klog.ErrorS(err, "OVSDB constraint violation")
	case *ovsdb.ReferentialIntegrityViolation:
		klog.ErrorS(err, "OVSDB referential integrity violation")
	case *ovsdb.DuplicateUUIDName:
		klog.ErrorS(err, "OVSDB duplicate named UUID")
	case *ovsdb.ResourcesExhausted:
		klog.ErrorS(err, "OVSDB resources exhausted")
	case *ovsdb.IOError:
		klog.ErrorS(err, "OVSDB I/O error")
	default:
		klog.ErrorS(opErr, "OVSDB operation failed")
	}
}
