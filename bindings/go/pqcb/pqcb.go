// Package pqcb provides Go bindings for PQC Bridge.
package pqcb

import "errors"

// Version is the binding version.
const Version = "0.1.0"

// BackendUnavailable is returned by v0.1 scaffold operations.
var BackendUnavailable = errors.New("pqcb backend is not configured in the v0.1 scaffold")

// CreateSecureSession is reserved for the high-level session API.
func CreateSecureSession() error {
	return BackendUnavailable
}
