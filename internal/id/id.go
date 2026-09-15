package id

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Names for agents and items. Infisical-style: lowercase, start with a letter.
var re = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)

// UUID is a Kratos identity id. Grant.AgentID holds it for a human grantee.
var uuid = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func Valid(s string) bool { return re.MatchString(s) }

func UUID(s string) bool { return uuid.MatchString(strings.TrimSpace(s)) }

// Principal is an agent name or a Kratos identity UUID.
func Principal(s string) bool { return Valid(s) || UUID(s) }

func Grant(agentID, itemID string) string { return agentID + ":" + itemID }

// NewItem is a random Infisical-style id. Display names are not ids.
func NewItem() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	s := "i" + hex.EncodeToString(b[:])
	if !Valid(s) {
		return "", fmt.Errorf("id: generated invalid item id")
	}
	return s, nil
}
