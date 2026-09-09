package id

import "regexp"

// Names for agents and items. Infisical-style: lowercase, start with a letter.
var re = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)

func Valid(s string) bool { return re.MatchString(s) }

func Grant(agentID, itemID string) string { return agentID + ":" + itemID }
