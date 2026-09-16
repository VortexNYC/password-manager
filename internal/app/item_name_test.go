package app

import (
	"testing"

	"github.com/veilnyc/password-manager/internal/id"
)

func TestPutItemKeepsHostAsDisplayName(t *testing.T) {
	a, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	item, err := a.PutItem(ItemOpts{
		Name:  "github.com",
		URI:   "https://github.com",
		Token: []byte(secret),
		Login: "ada",
	})
	if err != nil {
		t.Fatal(err)
	}
	if item.Name != "github.com" {
		t.Fatalf("chooser name %q", item.Name)
	}
	if item.ID == "github.com" || item.ID == "" || !id.Valid(item.ID) {
		t.Fatalf("id must be a generated slug, got %q", item.ID)
	}
	if item.ID == item.Name {
		t.Fatal("display name was used as Infisical id")
	}
}

func TestPutItemSlugNameIsStillTheID(t *testing.T) {
	a, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	item, err := a.PutItem(ItemOpts{Name: "github", URI: "https://github.com", Token: []byte(secret)})
	if err != nil {
		t.Fatal(err)
	}
	if item.ID != "github" || item.Name != "github" {
		t.Fatalf("%+v", item)
	}
}
