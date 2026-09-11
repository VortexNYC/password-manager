package glue

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeamKeepsOrySDKsInProductDirs(t *testing.T) {
	for _, name := range []string{"glue.go", "invite.go"} {
		raw, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "github.com/ory/") {
			t.Fatalf("%s imports an Ory SDK; that belongs in kratos/, hydra/, or keto/", name)
		}
	}
}
