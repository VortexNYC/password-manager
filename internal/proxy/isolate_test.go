package proxy

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.Unsetenv("VEIL_HYDRA_ISSUER")
	os.Exit(m.Run())
}
