package main

import (
	"fmt"
	"os"
)

const version = "0.0.1"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println(version)
		return
	}
	fmt.Fprintf(os.Stderr, `password-manager %s

Agent-first credential broker. Agents never hold secrets.

This binary is a stub. The engine lives in internal/ and is covered by tests.
Next: CLI + MCP that speak the same Use/Approve protocol.

https://github.com/VortexNYC/password-manager
`, version)
	os.Exit(2)
}
