package passgen

import (
	"strings"
	"testing"
	"unicode"
)

func TestRequiredSpecialIsNotAlphanumericOnly(t *testing.T) {
	got, err := FromRules("required: special; minlength: 16")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 16 {
		t.Fatalf("%q", got)
	}
	if !hasSpecial(got) {
		t.Fatalf("required: special produced no symbol: %q", got)
	}
}

func TestRequiredDigitUpperLower(t *testing.T) {
	got, err := FromRules("required: upper; required: lower; required: digit; minlength: 20")
	if err != nil {
		t.Fatal(err)
	}
	var upper, lower, digit bool
	for _, b := range got {
		switch {
		case b >= 'A' && b <= 'Z':
			upper = true
		case b >= 'a' && b <= 'z':
			lower = true
		case b >= '0' && b <= '9':
			digit = true
		}
	}
	if !upper || !lower || !digit {
		t.Fatalf("missing class upper=%v lower=%v digit=%v %q", upper, lower, digit, got)
	}
}

func TestFromRulesDefaultMatchesNew(t *testing.T) {
	got, err := FromRules("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 20 {
		t.Fatalf("default length %d", len(got))
	}
	for _, b := range got {
		if !inAlphabet(b) {
			t.Fatalf("default alphabet %q", got)
		}
	}
}

func TestFromRulesHonorsLength(t *testing.T) {
	got, err := FromRules("minlength: 32; maxlength: 40")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 {
		t.Fatalf("%d", len(got))
	}
	if _, err := FromRules("maxlength: 8"); err == nil {
		t.Fatal("short max")
	}
	if _, err := FromRules("minlength: 40; maxlength: 20"); err == nil {
		t.Fatal("min > max")
	}
}

func TestFromRulesAllowedRestrictsAlphabet(t *testing.T) {
	got, err := FromRules("allowed: digit; minlength: 12; maxlength: 12")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 12 {
		t.Fatalf("%d", len(got))
	}
	for _, b := range got {
		if b < '0' || b > '9' {
			t.Fatalf("outside allowed %q", got)
		}
	}
	if _, err := FromRules("allowed: digit; required: special; minlength: 12"); err == nil {
		t.Fatal("required outside allowed")
	}
}

func hasSpecial(b []byte) bool {
	for _, c := range b {
		if !unicode.IsLetter(rune(c)) && !unicode.IsDigit(rune(c)) && !unicode.IsSpace(rune(c)) {
			return true
		}
	}
	return strings.ContainsAny(string(b), specials)
}
