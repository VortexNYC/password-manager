package main

import (
	"fmt"
	"os"

	"github.com/vortexnyc/password-manager/internal/cli"
)

const version = "0.0.1"

func main() {
	if err := cli.New(version).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
