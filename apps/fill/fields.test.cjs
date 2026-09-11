const { test } = require("node:test");
const assert = require("node:assert/strict");
const { pickFields } = require("./fields.js");

function el(partial) {
  return Object.assign({ autocomplete: "", type: "text", name: "", id: "", hidden: false, disabled: false }, partial);
}

test("username and current-password from autocomplete", () => {
  const got = pickFields([
    el({ autocomplete: "username", name: "u" }),
    el({ autocomplete: "current-password", type: "password", name: "p" }),
  ]);
  assert.equal(got.username.name, "u");
  assert.equal(got.password.name, "p");
  assert.equal(got.totp, null);
});

test("new-password is not fill", () => {
  const got = pickFields([
    el({ autocomplete: "username" }),
    el({ autocomplete: "new-password", type: "password", name: "np" }),
  ]);
  assert.equal(got.password, null);
});

test("email type and password type without autocomplete", () => {
  const got = pickFields([el({ type: "email", name: "e" }), el({ type: "password", name: "p" })]);
  assert.equal(got.username.name, "e");
  assert.equal(got.password.name, "p");
});

test("one-time-code", () => {
  const got = pickFields([el({ autocomplete: "one-time-code", name: "otp" })]);
  assert.equal(got.totp.name, "otp");
});

test("empty is honest", () => {
  const got = pickFields([]);
  assert.equal(got.username, null);
  assert.equal(got.password, null);
  assert.equal(got.totp, null);
});
