const { test } = require("node:test");
const assert = require("node:assert/strict");
const { b64url, fromB64url, jsonCopy, credentialFromJSON } = require("./passkeys-page.js");

test("b64url roundtrip", () => {
  const buf = new Uint8Array([0, 1, 2, 254, 255]).buffer;
  const s = b64url(buf);
  assert.equal(s.includes("+"), false);
  assert.equal(s.includes("/"), false);
  assert.deepEqual(new Uint8Array(fromB64url(s)), new Uint8Array(buf));
});

test("jsonCopy encodes challenge buffers", () => {
  const challenge = new Uint8Array([1, 2, 3, 4]);
  const got = jsonCopy({ challenge: challenge, rpId: "webauthn.io" });
  assert.equal(typeof got.challenge, "string");
  assert.equal(got.rpId, "webauthn.io");
  assert.deepEqual(new Uint8Array(fromB64url(got.challenge)), challenge);
});

test("credentialFromJSON rebuilds attestation", () => {
  const client = b64url(new Uint8Array([9, 8, 7]));
  const att = b64url(new Uint8Array([1, 1, 1]));
  const cred = credentialFromJSON({
    id: "abc",
    rawId: "abc",
    type: "public-key",
    response: {
      clientDataJSON: client,
      attestationObject: att,
      authenticatorData: b64url(new Uint8Array([2])),
    },
  });
  assert.equal(cred.id, "abc");
  assert.equal(cred.type, "public-key");
  assert.ok(cred.response.attestationObject instanceof ArrayBuffer);
  assert.equal(cred.response.attestationObject.byteLength, 3);
});
