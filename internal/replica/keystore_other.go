//go:build !darwin

package replica

func Platform() KeyStore { return nil }
