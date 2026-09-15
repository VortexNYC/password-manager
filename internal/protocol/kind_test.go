package protocol

import "testing"

func TestCardAndIdentityDoNotInject(t *testing.T) {
	if ItemCard.Injects() || ItemIdentity.Injects() || ItemPasskey.Injects() {
		t.Fatal("fill kinds must not inject")
	}
	if !ItemAPIKey.Injects() {
		t.Fatal("api_key injects")
	}
}

func TestFillableKinds(t *testing.T) {
	for _, k := range []ItemKind{ItemAPIKey, ItemPasskey, ItemCard, ItemIdentity} {
		if !k.Fillable() {
			t.Fatalf("%s fillable", k)
		}
	}
	for _, k := range []ItemKind{ItemOAuth, ItemSSH, ItemFile} {
		if k.Fillable() {
			t.Fatalf("%s not fillable", k)
		}
	}
}
