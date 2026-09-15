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

func TestActionStripsVeilWantsTo(t *testing.T) {
	if Action("Veil wants to fill a card") != "fill a card" {
		t.Fatalf("%q", Action("Veil wants to fill a card"))
	}
	if Action("get CLI access") != "get CLI access" {
		t.Fatalf("%q", Action("get CLI access"))
	}
	if Action("") != "use Veil" {
		t.Fatalf("%q", Action(""))
	}
}

func TestCLIAccessOffIsNoop(t *testing.T) {
	t.Setenv("PWM_FILL_TOUCHID", "0")
	if err := CLIAccess(); err != nil {
		t.Fatal(err)
	}
}
