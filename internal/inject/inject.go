// Package inject rewrites a template using granted item names.
//
// Infisical placeholder shape: ${NAME}. pwm://name is the same lookup.
// Resolution happens inside the broker for a child file. The expanded
// bytes are not an agent-visible type.
package inject

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vortexnyc/password-manager/internal/broker"
)

var ref = regexp.MustCompile(`\$\{([A-Za-z0-9_-]+)\}|pwm://([A-Za-z0-9_-]+)`)

// Map is EnvName(item) -> value from ChildEnv pairs.
func Map(pairs []string) map[string]string {
	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// Expand replaces ${ITEM} and pwm://item. Unknown refs fail closed.
func Expand(src []byte, granted map[string]string) ([]byte, error) {
	var first error
	out := ref.ReplaceAllFunc(src, func(raw []byte) []byte {
		m := ref.FindSubmatch(raw)
		name := ""
		if len(m) > 1 {
			name = string(m[1])
		}
		if name == "" && len(m) > 2 {
			name = string(m[2])
		}
		key := broker.EnvName(name)
		v, ok := granted[key]
		if !ok {
			if first == nil {
				first = fmt.Errorf("inject: unknown ref %s", name)
			}
			return raw
		}
		return []byte(v)
	})
	if first != nil {
		return nil, first
	}
	return out, nil
}
