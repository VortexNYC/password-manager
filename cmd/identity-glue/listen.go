package main

import (
	"os"
	"strings"
)

func listenAddr() string {
	if v := strings.TrimSpace(os.Getenv("GLUE_LISTEN")); v != "" {
		return v
	}
	if p := strings.TrimSpace(os.Getenv("PORT")); p != "" {
		if strings.Contains(p, ":") {
			return p
		}
		return ":" + p
	}
	return "127.0.0.1:4456"
}
