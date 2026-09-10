package cli

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.Unsetenv("PWM_HYDRA_ISSUER")
	_ = os.Unsetenv("PWM_HYDRA_ADMIN")
	_ = os.Unsetenv("PWM_HOME")
	_ = os.Unsetenv("PWM_OIDC_TOKEN")
	_ = os.Unsetenv("PWM_OIDC_TOKEN_FILE")
	_ = os.Unsetenv("PWM_ORIGIN")
	_ = os.Unsetenv("PWM_HYDRA_SECRET_FILE")
	_ = os.Unsetenv("PWM_AGENT")
	os.Exit(m.Run())
}
