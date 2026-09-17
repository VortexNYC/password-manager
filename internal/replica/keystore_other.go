//go:build !darwin

package replica

import "os"

func Platform() KeyStore {
	if os.Getenv("VEIL_REPLICA_KEYSTORE") == "mem" {
		return Mem()
	}
	return nil
}
