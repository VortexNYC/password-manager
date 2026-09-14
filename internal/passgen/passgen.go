package passgen

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
)

const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
const lettersUpper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
const lettersLower = "abcdefghijkmnopqrstuvwxyz"
const digits = "23456789"
const specials = "-~!@#$%^&*_+"
const asciiPrintable = lettersUpper + lettersLower + digits + specials + "=?/;:,.()"

func New(n int) ([]byte, error) {
	return fromAlphabet(n, alphabet)
}

func FromRules(rules string) ([]byte, error) {
	spec, err := parseRules(rules)
	if err != nil {
		return nil, err
	}
	out, err := fromAlphabet(spec.n, spec.alphabet)
	if err != nil {
		return nil, err
	}
	for i, class := range spec.required {
		pick, err := pickByte(class)
		if err != nil {
			return nil, err
		}
		out[i] = pick
	}
	if err := shuffle(out); err != nil {
		return nil, err
	}
	return out, nil
}

type ruleSpec struct {
	n        int
	alphabet string
	required []string
}

func parseRules(rules string) (ruleSpec, error) {
	n := 20
	minN, maxN := 12, 128
	var required []string
	var allowed []string
	for _, part := range strings.Split(rules, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, val, found := strings.Cut(part, ":")
		if !found {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch key {
		case "minlength":
			v, err := strconv.Atoi(val)
			if err != nil {
				return ruleSpec{}, err
			}
			minN = v
		case "maxlength":
			v, err := strconv.Atoi(val)
			if err != nil {
				return ruleSpec{}, err
			}
			maxN = v
		case "required":
			required = append(required, splitClasses(val)...)
		case "allowed":
			allowed = append(allowed, splitClasses(val)...)
		}
	}
	if minN > maxN {
		return ruleSpec{}, fmt.Errorf("passgen: minlength > maxlength")
	}
	if minN > n {
		n = minN
	}
	if maxN < n {
		n = maxN
	}
	if n < 12 || n > 128 {
		return ruleSpec{}, fmt.Errorf("passgen: length must be 12-128")
	}
	if len(required) > n {
		return ruleSpec{}, fmt.Errorf("passgen: too many required classes")
	}
	alpha := alphabet
	if len(allowed) > 0 {
		alpha = ""
		for _, class := range allowed {
			alpha = unionAlphabet(alpha, class)
		}
	}
	for _, class := range required {
		need := classAlphabet(class)
		if need == "" {
			return ruleSpec{}, fmt.Errorf("passgen: unknown class %q", class)
		}
		if len(allowed) > 0 {
			ok := false
			for i := 0; i < len(need); i++ {
				if strings.IndexByte(alpha, need[i]) >= 0 {
					ok = true
					break
				}
			}
			if !ok {
				return ruleSpec{}, fmt.Errorf("passgen: required class not allowed")
			}
		} else {
			alpha = unionAlphabet(alpha, class)
		}
	}
	if alpha == "" {
		return ruleSpec{}, fmt.Errorf("passgen: empty alphabet")
	}
	return ruleSpec{n: n, alphabet: alpha, required: required}, nil
}

func splitClasses(val string) []string {
	val = strings.Trim(val, "[]")
	parts := strings.FieldsFunc(val, func(r rune) bool {
		return r == ',' || r == ' '
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func unionAlphabet(have, class string) string {
	add := classAlphabet(class)
	if add == "" {
		return have
	}
	seen := make(map[byte]struct{}, len(have)+len(add))
	var b strings.Builder
	for i := 0; i < len(have); i++ {
		c := have[i]
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		b.WriteByte(c)
	}
	for i := 0; i < len(add); i++ {
		c := add[i]
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		b.WriteByte(c)
	}
	return b.String()
}

func classAlphabet(class string) string {
	switch class {
	case "upper", "uppercase":
		return lettersUpper
	case "lower", "lowercase":
		return lettersLower
	case "digit", "digits":
		return digits
	case "special", "special-char", "special-chars":
		return specials
	case "ascii-printable":
		return asciiPrintable
	default:
		return ""
	}
}

func fromAlphabet(n int, alpha string) ([]byte, error) {
	if n < 12 || n > 128 {
		return nil, fmt.Errorf("passgen: length must be 12-128")
	}
	if alpha == "" {
		return nil, fmt.Errorf("passgen: empty alphabet")
	}
	out := make([]byte, n)
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	for i, b := range buf {
		out[i] = alpha[int(b)%len(alpha)]
	}
	return out, nil
}

func pickByte(class string) (byte, error) {
	alpha := classAlphabet(class)
	if alpha == "" {
		return 0, fmt.Errorf("passgen: unknown class %q", class)
	}
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return alpha[int(b[0])%len(alpha)], nil
}

func shuffle(out []byte) error {
	buf := make([]byte, len(out))
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	for i := len(out) - 1; i > 0; i-- {
		j := int(buf[i]) % (i + 1)
		out[i], out[j] = out[j], out[i]
	}
	return nil
}
