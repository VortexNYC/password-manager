package inject

import (
	"strings"
	"testing"

	"github.com/vortexnyc/password-manager/internal/scrub"
)

func TestExpandGrantedNameDoesNotLeakOnUnknown(t *testing.T) {
	secret := "sk_live_INJECT_SECRET"
	got, err := Expand([]byte("token=${STRIPE}\n"), Map([]string{"STRIPE=" + secret}))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "token="+secret+"\n" {
		t.Fatalf("%q", got)
	}
	_, err = Expand([]byte("token=${MISSING}\n"), Map([]string{"STRIPE=" + secret}))
	if err == nil {
		t.Fatal("expected unknown ref")
	}
	if scrub.Contains([]byte(err.Error()), []byte(secret)) {
		t.Fatalf("error leaked secret: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal(err)
	}
}

func TestExpandPWMURIAndHyphenName(t *testing.T) {
	secret := "sk_hyphen"
	got, err := Expand([]byte("pwm://my-key"), Map([]string{"MY_KEY=" + secret}))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != secret {
		t.Fatalf("%q", got)
	}
}
