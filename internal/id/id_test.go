package id

import "testing"

func TestValid(t *testing.T) {
	ok := []string{"stripe", "claude", "gh-pat", "a1"}
	for _, s := range ok {
		if !Valid(s) {
			t.Fatalf("%q should be valid", s)
		}
	}
	bad := []string{"", "A", "1x", "Stripe", "has_underscore", "x/y"}
	for _, s := range bad {
		if Valid(s) {
			t.Fatalf("%q should be invalid", s)
		}
	}
}

func TestGrant(t *testing.T) {
	if Grant("claude", "stripe") != "claude:stripe" {
		t.Fatal(Grant("claude", "stripe"))
	}
}
