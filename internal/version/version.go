// SPDX-FileCopyrightText: 2026 <UNVEILR LEGAL ENTITY>
// SPDX-License-Identifier: AGPL-3.0-only

package version

// Version is the CLI version.
//
// "dev" is the honest default for a build that nobody stamped. It used to read
// "0.1.0", which meant every local build, every fork and every `go install`
// claimed to be a release that had never been cut — and the constant had not
// moved since the repository was created. A binary that misreports its version
// makes the first question of any bug report useless.
//
// Releases override it:
//
//	go build -ldflags "-X go.unveilr.ai/guard/internal/version.Version=$(git describe --tags)" ./cmd/unveilr
var Version = "dev"
