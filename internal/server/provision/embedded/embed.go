// Package embedded carries the files the provisioner installs on targets.
//
// The update guard is embedded (not read from the repo at runtime) so an
// INSTALLED server — no repo checkout next to the binary — can provision
// agents with M8.1 rollback protection. embed_test.go pins the embedded
// copy to the repo's deploy/systemd source of truth.
package embedded

import _ "embed"

// UpdateGuard is the M8.1 boot guard (deploy/systemd/partout-update-guard.sh).
//
//go:embed partout-update-guard.sh
var UpdateGuard string
