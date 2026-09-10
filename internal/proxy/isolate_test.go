package proxy

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.Unsetenv("PWM_HYDRA_ISSUER")
	os.Exit(m.Run())
}
