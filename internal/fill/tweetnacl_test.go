package fill

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func tweetNaClPath(t *testing.T) (naclJS, utilJS, clientJS string) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(home, "Library/Application Support/Google/Chrome/Profile 2/Extensions/oboonakemofpalcgghocfoadofidjkkk/1.10.3_0/background")
	naclJS = filepath.Join(base, "nacl.min.js")
	utilJS = filepath.Join(base, "nacl-util.min.js")
	if _, err := os.Stat(naclJS); err != nil {
		t.Skip("keepassxc-browser nacl.min.js not installed")
	}
	if _, err := os.Stat(utilJS); err != nil {
		t.Skip("keepassxc-browser nacl-util.min.js not installed")
	}
	clientJS = filepath.Join("testdata", "tweetnacl_client.cjs")
	return naclJS, utilJS, clientJS
}

func tweetNaCl(t *testing.T, naclJS, utilJS, clientJS string, in map[string]string) map[string]string {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", clientJS, naclJS, utilJS)
	cmd.Stdin = bytes.NewReader(raw)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tweetnacl: %v\n%s", err, out)
	}
	var got map[string]string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("tweetnacl json: %v\n%s", err, out)
	}
	if got["error"] != "" {
		t.Fatalf("tweetnacl %s: %s", in["op"], got["error"])
	}
	return got
}

func TestTweetNaClIncrementMatchesGo(t *testing.T) {
	naclJS, utilJS, clientJS := tweetNaClPath(t)
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	// Force a carry so JS Uint8Array wrap is exercised.
	nonce[0] = 255
	src := base64.StdEncoding.EncodeToString(nonce)
	js := tweetNaCl(t, naclJS, utilJS, clientJS, map[string]string{"op": "increment", "nonce": src})
	var n [24]byte
	copy(n[:], nonce)
	want := bumpNonce(n)
	if js["nonce"] != base64.StdEncoding.EncodeToString(want[:]) {
		t.Fatalf("js %q go %q", js["nonce"], base64.StdEncoding.EncodeToString(want[:]))
	}
}

func TestTweetNaClOpensGoDatabaseHash(t *testing.T) {
	naclJS, utilJS, clientJS := tweetNaClPath(t)
	kp := tweetNaCl(t, naclJS, utilJS, clientJS, map[string]string{"op": "keypair"})
	h := New(vault(t))
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	keys, err := json.Marshal(envelope{
		Action:    "change-public-keys",
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		ClientID:  "tweetnacl-1",
		PublicKey: kp["publicKey"],
	})
	if err != nil {
		t.Fatal(err)
	}
	var keysGot envelope
	if err := json.Unmarshal(h.Handle(keys), &keysGot); err != nil {
		t.Fatal(err)
	}
	if keysGot.PublicKey == "" {
		t.Fatalf("%+v", keysGot)
	}
	jsInc := tweetNaCl(t, naclJS, utilJS, clientJS, map[string]string{"op": "increment", "nonce": base64.StdEncoding.EncodeToString(nonce)})
	if keysGot.Nonce != jsInc["nonce"] {
		t.Fatalf("change-public-keys nonce js %q host %q", jsInc["nonce"], keysGot.Nonce)
	}

	hashNonce := make([]byte, 24)
	if _, err := rand.Read(hashNonce); err != nil {
		t.Fatal(err)
	}
	hashNonceB64 := base64.StdEncoding.EncodeToString(hashNonce)
	boxed := tweetNaCl(t, naclJS, utilJS, clientJS, map[string]string{
		"op":       "box",
		"plain":    `{"action":"get-databasehash"}`,
		"nonce":    hashNonceB64,
		"theirPub": keysGot.PublicKey,
		"secret":   kp["secretKey"],
	})
	req, err := json.Marshal(envelope{
		Action:   "get-databasehash",
		Message:  boxed["message"],
		Nonce:    hashNonceB64,
		ClientID: "tweetnacl-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(h.Handle(req), &env); err != nil {
		t.Fatal(err)
	}
	if env.Action != "get-databasehash" {
		t.Fatalf("outer action %q", env.Action)
	}
	wantNonce := tweetNaCl(t, naclJS, utilJS, clientJS, map[string]string{"op": "increment", "nonce": hashNonceB64})["nonce"]
	if env.Nonce != wantNonce {
		t.Fatalf("outer nonce js %q host %q", wantNonce, env.Nonce)
	}
	opened := tweetNaCl(t, naclJS, utilJS, clientJS, map[string]string{
		"op":       "open",
		"message":  env.Message,
		"nonce":    env.Nonce,
		"theirPub": keysGot.PublicKey,
		"secret":   kp["secretKey"],
	})
	var parsed map[string]string
	if err := json.Unmarshal([]byte(opened["plain"]), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["success"] != "true" || parsed["hash"] == "" {
		t.Fatalf("%v", parsed)
	}
	if parsed["nonce"] != wantNonce {
		t.Fatalf("inner nonce %q want %q", parsed["nonce"], wantNonce)
	}
}

func TestTweetNaClNativeFrames(t *testing.T) {
	naclJS, utilJS, clientJS := tweetNaClPath(t)
	kp := tweetNaCl(t, naclJS, utilJS, clientJS, map[string]string{"op": "keypair"})
	h := New(vault(t))
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- h.Serve(inR, outW) }()
	t.Cleanup(func() {
		_ = inW.Close()
		_ = outW.Close()
		<-done
	})

	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	keys, err := json.Marshal(envelope{
		Action:    "change-public-keys",
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		ClientID:  "tweetnacl-frame",
		PublicKey: kp["publicKey"],
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(inW, keys); err != nil {
		t.Fatal(err)
	}
	raw, err := Read(outR)
	if err != nil {
		t.Fatal(err)
	}
	var keysGot envelope
	if err := json.Unmarshal(raw, &keysGot); err != nil {
		t.Fatal(err)
	}

	hashNonce := make([]byte, 24)
	if _, err := rand.Read(hashNonce); err != nil {
		t.Fatal(err)
	}
	hashNonceB64 := base64.StdEncoding.EncodeToString(hashNonce)
	boxed := tweetNaCl(t, naclJS, utilJS, clientJS, map[string]string{
		"op":       "box",
		"plain":    `{"action":"get-databasehash"}`,
		"nonce":    hashNonceB64,
		"theirPub": keysGot.PublicKey,
		"secret":   kp["secretKey"],
	})
	req, err := json.Marshal(envelope{
		Action:   "get-databasehash",
		Message:  boxed["message"],
		Nonce:    hashNonceB64,
		ClientID: "tweetnacl-frame",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(inW, req); err != nil {
		t.Fatal(err)
	}
	raw, err = Read(outR)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	opened := tweetNaCl(t, naclJS, utilJS, clientJS, map[string]string{
		"op":       "open",
		"message":  env.Message,
		"nonce":    env.Nonce,
		"theirPub": keysGot.PublicKey,
		"secret":   kp["secretKey"],
	})
	var parsed map[string]string
	if err := json.Unmarshal([]byte(opened["plain"]), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["success"] != "true" || parsed["hash"] == "" {
		t.Fatalf("%v", parsed)
	}
}
