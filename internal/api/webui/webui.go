// Package webui embeds the Partout web UI (PRD §11, ui-guidelines S0).
//
// The UI is a buildless Vue 3 SPA: index.html + app.js + style.css with the
// Vue runtime vendored in lib/ so a deployed binary needs no Node toolchain
// and works fully offline (ui-guidelines decision 12, minus the Vite step —
// the source is the artifact). It is served same-origin on the main listener
// (hard constraint 1): no CORS, no separate origin.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed index.html app.js style.css lib
var assets embed.FS

// FS returns the embedded UI file system rooted at the package directory.
func FS() fs.FS { return assets }

// IndexHTML is the SPA entry document, served for "/" and for any
// non-asset, non-API path (the client-side router owns those paths).
func IndexHTML() []byte {
	b, err := assets.ReadFile("index.html")
	if err != nil {
		return nil
	}
	return b
}
