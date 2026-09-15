package absurl

import (
	"fmt"
	"net/url"
	"strings"
)

func Parse(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("need an absolute URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("need an absolute URL")
	}
	return u.String(), nil
}
