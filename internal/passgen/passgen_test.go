package passgen

import "testing"

func TestNewLengthAndAlphabet(t *testing.T) {
	got, err := New(12)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 12 {
		t.Fatalf("%q", got)
	}
	for _, b := range got {
		if !inAlphabet(b) {
			t.Fatalf("bad byte %q", b)
		}
	}
	if _, err := New(11); err == nil {
		t.Fatal("short")
	}
	if _, err := New(129); err == nil {
		t.Fatal("long")
	}
}

func inAlphabet(b byte) bool {
	for i := 0; i < len(alphabet); i++ {
		if alphabet[i] == b {
			return true
		}
	}
	return false
}
