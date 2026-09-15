package main

import (
	"fmt"
	"os"

	"github.com/vortexnyc/password-manager/internal/cli"
	"github.com/vortexnyc/password-manager/internal/fill"
)

const version = "0.0.1"

func main() {
	os.Args = fill.NativeHostArgs(os.Args)
	if err := cli.New(version).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
