// Package passkey is the fill authenticator. We are not the relying party.
// go-webauthn is site-side (Kratos). This package mints ES256 credentials
// and assertions on the keepassxc-browser passkeys-* wire.
package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/net/publicsuffix"
)

const (
	algES256 = -7
	flagUP   = 1 << 0
	flagUV   = 1 << 2
	flagAT   = 1 << 6
)

// Keepassxc-browser errorCode values. Inner `response.errorCode`.
const (
	ErrNoLogins        = 15
	ErrExcluded        = 21
	ErrInvalidURL      = 25
	ErrRPIDMismatch    = 28
	ErrNoSupportedAlgs = 29
	ErrUnknown         = 31
)

type Credential struct {
	AuthenticatorAttachment string             `json:"authenticatorAttachment"`
	ID                      string             `json:"id"`
	Type                    string             `json:"type"`
	Response                CredentialResponse `json:"response"`
}

type CredentialResponse struct {
	AttestationObject      string         `json:"attestationObject,omitempty"`
	AuthenticatorData      string         `json:"authenticatorData"`
	ClientDataJSON         string         `json:"clientDataJSON"`
	PublicKey              string         `json:"publicKey,omitempty"`
	PublicKeyAlgorithm     int            `json:"publicKeyAlgorithm,omitempty"`
	Signature              string         `json:"signature,omitempty"`
	UserHandle             string         `json:"userHandle,omitempty"`
	ClientExtensionResults map[string]any `json:"clientExtensionResults,omitempty"`
}

// Record is sealed vault material. Never on protocol.Item or MCP.
type Record struct {
	PEM        string
	CredID     string
	RpID       string
	UserHandle string
	UserName   string
}

type pubKeyJSON struct {
	Challenge          string     `json:"challenge"`
	RpID               string     `json:"rpId"`
	Attestation        string     `json:"attestation"`
	UserVerification   string     `json:"userVerification"`
	RP                 rpJSON     `json:"rp"`
	User               userJSON   `json:"user"`
	PubKeyCredParams   []algJSON  `json:"pubKeyCredParams"`
	ExcludeCredentials []credJSON `json:"excludeCredentials"`
	AllowCredentials   []credJSON `json:"allowCredentials"`
}

type rpJSON struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type userJSON struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type algJSON struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type credJSON struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type coseKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

type attObj struct {
	Fmt      string         `cbor:"fmt"`
	AttStmt  map[string]any `cbor:"attStmt"`
	AuthData []byte         `cbor:"authData"`
}

func Register(origin string, publicKey json.RawMessage, existing []Record) (Credential, Record, int) {
	pk, code := parse(publicKey)
	if code != 0 {
		return Credential{}, Record{}, code
	}
	if !originOK(origin) {
		return Credential{}, Record{}, ErrInvalidURL
	}
	originHost := hostOf(origin)
	rpID := pk.RP.ID
	if rpID == "" {
		rpID = originHost
	}
	if !rpIDOK(rpID, originHost) {
		return Credential{}, Record{}, ErrRPIDMismatch
	}
	if !allowsES256(pk.PubKeyCredParams) {
		return Credential{}, Record{}, ErrNoSupportedAlgs
	}
	if pk.User.ID == "" || pk.Challenge == "" {
		return Credential{}, Record{}, ErrUnknown
	}
	for _, ex := range pk.ExcludeCredentials {
		for _, have := range existing {
			if have.RpID == rpID && have.CredID == ex.ID {
				return Credential{}, Record{}, ErrExcluded
			}
		}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Credential{}, Record{}, ErrUnknown
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		return Credential{}, Record{}, ErrUnknown
	}
	credB64 := b64url(credID)
	cose, err := encodeCOSE(&priv.PublicKey)
	if err != nil {
		return Credential{}, Record{}, ErrUnknown
	}
	full := authData(rpID, flagUP|flagUV|flagAT, credID, cose)
	short := authData(rpID, flagUP|flagUV, nil, nil)
	att, err := encodeAttestation(full)
	if err != nil {
		return Credential{}, Record{}, ErrUnknown
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return Credential{}, Record{}, ErrUnknown
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Credential{}, Record{}, ErrUnknown
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	client := clientData("webauthn.create", pk.Challenge, origin)
	cred := Credential{
		AuthenticatorAttachment: "platform",
		ID:                      credB64,
		Type:                    "public-key",
		Response: CredentialResponse{
			AttestationObject:  b64url(att),
			AuthenticatorData:  b64url(short),
			ClientDataJSON:     b64url(client),
			PublicKey:          b64url(spki),
			PublicKeyAlgorithm: algES256,
		},
	}
	rec := Record{
		PEM:        string(pemBytes),
		CredID:     credB64,
		RpID:       rpID,
		UserHandle: pk.User.ID,
		UserName:   pk.User.Name,
	}
	return cred, rec, 0
}

func Assert(origin string, publicKey json.RawMessage, recs []Record) (Credential, int) {
	pk, code := parse(publicKey)
	if code != 0 {
		return Credential{}, code
	}
	if !originOK(origin) {
		return Credential{}, ErrInvalidURL
	}
	originHost := hostOf(origin)
	rpID := pk.RpID
	if rpID == "" {
		rpID = originHost
	}
	if !rpIDOK(rpID, originHost) {
		return Credential{}, ErrRPIDMismatch
	}
	if pk.Challenge == "" {
		return Credential{}, ErrUnknown
	}
	var rec Record
	found := false
	for _, r := range recs {
		if r.RpID != rpID {
			continue
		}
		if len(pk.AllowCredentials) > 0 && !allowed(pk.AllowCredentials, r.CredID) {
			continue
		}
		rec = r
		found = true
		break
	}
	if !found {
		return Credential{}, ErrNoLogins
	}
	priv, err := parsePEM(rec.PEM)
	if err != nil {
		return Credential{}, ErrUnknown
	}
	short := authData(rpID, flagUP|flagUV, nil, nil)
	client := clientData("webauthn.get", pk.Challenge, origin)
	sum := sha256.Sum256(client)
	msg := append(append([]byte{}, short...), sum[:]...)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, msg)
	if err != nil {
		return Credential{}, ErrUnknown
	}
	return Credential{
		AuthenticatorAttachment: "platform",
		ID:                      rec.CredID,
		Type:                    "public-key",
		Response: CredentialResponse{
			AuthenticatorData: b64url(short),
			ClientDataJSON:    b64url(client),
			Signature:         b64url(sig),
			UserHandle:        rec.UserHandle,
		},
	}, 0
}

func ErrorResponse(code int) json.RawMessage {
	raw, err := json.Marshal(map[string]int{"errorCode": code})
	if err != nil {
		return json.RawMessage(`{"errorCode":31}`)
	}
	return raw
}

func parse(raw json.RawMessage) (pubKeyJSON, int) {
	var pk pubKeyJSON
	if len(raw) == 0 || json.Unmarshal(raw, &pk) != nil {
		return pk, ErrUnknown
	}
	return pk, 0
}

func originOK(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return true
	case "http":
		h := strings.ToLower(u.Hostname())
		return h == "localhost" || h == "127.0.0.1"
	default:
		return false
	}
}

func hostOf(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func rpIDOK(rpID, host string) bool {
	rpID = strings.ToLower(strings.TrimSpace(rpID))
	host = strings.ToLower(host)
	if rpID == "" || host == "" {
		return false
	}
	if rpID == host {
		return true
	}
	if host == "localhost" || host == "127.0.0.1" {
		return rpID == "localhost"
	}
	if !strings.HasSuffix(host, "."+rpID) {
		return false
	}
	suffix, icann := publicsuffix.PublicSuffix(rpID)
	if icann && suffix == rpID {
		return false
	}
	return true
}

func allowsES256(params []algJSON) bool {
	if len(params) == 0 {
		return true
	}
	for _, p := range params {
		if p.Alg == algES256 {
			return true
		}
	}
	return false
}

func allowed(list []credJSON, id string) bool {
	for _, c := range list {
		if c.ID == id {
			return true
		}
	}
	return false
}

func clientData(kind, challenge, origin string) []byte {
	type cd struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	raw, err := json.Marshal(cd{Type: kind, Challenge: challenge, Origin: origin})
	if err != nil {
		return []byte(`{}`)
	}
	return raw
}

func authData(rpID string, flags byte, credID, cose []byte) []byte {
	sum := sha256.Sum256([]byte(rpID))
	buf := make([]byte, 0, 37+len(credID)+len(cose)+18)
	buf = append(buf, sum[:]...)
	buf = append(buf, flags)
	buf = append(buf, 0, 0, 0, 0)
	if flags&flagAT == 0 {
		return buf
	}
	buf = append(buf, make([]byte, 16)...)
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(credID)))
	buf = append(buf, n[:]...)
	buf = append(buf, credID...)
	buf = append(buf, cose...)
	return buf
}

func encodeCOSE(pub *ecdsa.PublicKey) ([]byte, error) {
	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return mode.Marshal(coseKey{
		Kty: 2,
		Alg: algES256,
		Crv: 1,
		X:   padded(pub.X.Bytes(), 32),
		Y:   padded(pub.Y.Bytes(), 32),
	})
}

func encodeAttestation(auth []byte) ([]byte, error) {
	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return mode.Marshal(attObj{
		Fmt:      "none",
		AttStmt:  map[string]any{},
		AuthData: auth,
	})
}

func parsePEM(raw string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("passkey: pem")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("passkey: not ecdsa")
	}
	return priv, nil
}

func padded(b []byte, n int) []byte {
	if len(b) == n {
		return b
	}
	out := make([]byte, n)
	if len(b) > n {
		copy(out, b[len(b)-n:])
		return out
	}
	copy(out[n-len(b):], b)
	return out
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func DecodeB64(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func ItemName(rpID, userHandle string) string {
	sum := sha256.Sum256([]byte(rpID + "\x00" + userHandle))
	return "pk-" + hex.EncodeToString(sum[:8])
}
