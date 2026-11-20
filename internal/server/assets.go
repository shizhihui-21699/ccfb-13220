package server

import (
	"embed"
	"io/fs"
	"strings"
)

// distFS holds the built React app. The "dist/.gitkeep" placeholder keeps the
// directory present before a build, so `go build` works without npm.
//
//go:embed all:dist
var distFS embed.FS

var assets = loadAssets()

func loadAssets() map[string][]byte {
	out := map[string][]byte{}
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return out
	}
	entries, err := fs.ReadDir(sub, ".")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := fs.ReadFile(sub, e.Name())
		if err != nil {
			continue
		}
		// Hidden placeholder files (dist/.gitkeep) keep the embed directive
		// valid before the UI is built; never serve them.
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		out[e.Name()] = data
	}
	return out
}
