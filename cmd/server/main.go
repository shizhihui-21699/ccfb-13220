// Command server runs the historyscrub operator UI and JSON API.
package main

import (
	"flag"
	"fmt"
	"os"

	"historyscrub/internal/server"
)

func main() {
	root := flag.String("root", ".", "directory the repo browser may look in; paths cannot escape it")
	addr := flag.String("addr", "127.0.0.1:8765", "listen address")
	allowRun := flag.Bool("allow-run", false, "enable mutating endpoints (run, prune). Off by default.")
	flag.Parse()

	srv, err := server.New(server.Config{Root: *root, Addr: *addr, AllowRun: *allowRun})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		os.Exit(1)
	}
	if err := srv.Listen(); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		os.Exit(1)
	}
}
