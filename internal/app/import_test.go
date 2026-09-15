package app

import (
	"testing"

	"github.com/vortexnyc/password-manager/internal/material"
	"github.com/vortexnyc/password-manager/internal/oneimport"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/scrub"
)

func TestImportItemsCreatesLoginAndCard(t *testing.T) {
	a, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	const pan = "4111111111111111"
	const pass = "s3cret"
	blob, err := material.PackCard(pan, "12", "2030", "123", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: "self", OrgID: protocol.LocalOrgID}
	got, err := a.ImportItems(human, []oneimport.Row{
		{Name: "GitHub", Kind: protocol.ItemAPIKey, URIs: []string{"https://github.com"}, Login: "ada", Token: []byte(pass)},
		{Name: "Amex", Kind: protocol.ItemCard, Token: blob},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Count != 2 || got.Names[0] != "GitHub" || got.Names[1] != "Amex" {
		t.Fatalf("%+v", got)
	}
	items, err := a.Store.ListItems()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jsonNames(items)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(raw, []byte(pass)) || scrub.Contains(raw, []byte(pan)) {
		t.Fatal("list leaked secret")
	}
}

func TestImportItemsDuplicateNames(t *testing.T) {
	a, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: "self", OrgID: protocol.LocalOrgID}
	got, err := a.ImportItems(human, []oneimport.Row{
		{Name: "Microsoft", Token: []byte("a")},
		{Name: "Microsoft", Token: []byte("b")},
		{Name: "Microsoft", Token: []byte("c")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Count != 3 || got.Names[0] != "Microsoft" || got.Names[1] != "Microsoft (2)" || got.Names[2] != "Microsoft (3)" {
		t.Fatalf("%+v", got)
	}
	items, err := a.Store.ListItems()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("n=%d", len(items))
	}
}

func TestImportItemsRejectsAgent(t *testing.T) {
	a, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	agent := protocol.Principal{Kind: protocol.PrincipalAgent, ID: "claude", OrgID: protocol.LocalOrgID}
	if _, err := a.ImportItems(agent, []oneimport.Row{{Name: "x", Token: []byte("p")}}); err == nil {
		t.Fatal("expected error")
	}
}

func jsonNames(items []protocol.Item) ([]byte, error) {
	var b []byte
	for _, it := range items {
		b = append(b, it.Name...)
		b = append(b, it.Login...)
		for _, u := range it.URIs {
			b = append(b, u...)
		}
	}
	return b, nil
}
