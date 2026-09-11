package confirm

import (
	"testing"
)

func TestEnabledOff(t *testing.T) {
	t.Setenv("PWM_FILL_TOUCHID", "0")
	if Enabled() {
		t.Fatal("touch id on with PWM_FILL_TOUCHID=0")
	}
}
