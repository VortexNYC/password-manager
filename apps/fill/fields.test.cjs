const { test } = require("node:test");
const assert = require("node:assert/strict");
const { pickFields } = require("./fields.js");

function el(partial) {
  const node = Object.assign({ autocomplete: "", type: "text", name: "", id: "", hidden: false, disabled: false }, partial);
  node.getAttribute = function (name) {
    if (name === "autocomplete") {
      return this.autocomplete || "";
    }
    if (name === "data-autocomplete") {
      return this["data-autocomplete"] || "";
    }
    return "";
  };
  return node;
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

test("data-autocomplete new-password is generate", () => {
  const np = el({ autocomplete: "", "data-autocomplete": "new-password", type: "password", name: "np" });
  const got = pickFields([np]);
  assert.equal(got.password, null);
  assert.equal(got.newPassword.length, 1);
  assert.equal(got.newPassword[0].name, "np");
});

test("new-password is generate, not current-password fill", () => {
  const np = el({ autocomplete: "new-password", type: "password", name: "np" });
  const got = pickFields([el({ autocomplete: "username" }), np]);
  assert.equal(got.password, null);
  assert.equal(got.newPassword.length, 1);
  assert.equal(got.newPassword[0].name, "np");
});

test("two new-password fields are one generated value", () => {
  const got = pickFields([
    el({ autocomplete: "new-password", type: "password", name: "p1" }),
    el({ autocomplete: "new-password", type: "password", name: "p2" }),
  ]);
  assert.equal(got.newPassword.length, 2);
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
  assert.deepEqual(got.newPassword, []);
  assert.equal(got.number, null);
  assert.equal(got.cvv, null);
});

test("cc-number and cc-csc", () => {
  const got = pickFields([
    el({ autocomplete: "cc-number", name: "num" }),
    el({ autocomplete: "cc-csc", name: "cvc" }),
    el({ autocomplete: "cc-exp-month", name: "em" }),
    el({ autocomplete: "cc-exp-year", name: "ey" }),
  ]);
  assert.equal(got.number.name, "num");
  assert.equal(got.cvv.name, "cvc");
  assert.equal(got.expMonth.name, "em");
  assert.equal(got.expYear.name, "ey");
});

test("identity autocomplete", () => {
  const { pickFields, isFillTarget } = require("./fields.js");
  const got = pickFields([
    el({ autocomplete: "given-name", name: "fn" }),
    el({ autocomplete: "family-name", name: "ln" }),
    el({ autocomplete: "street-address", name: "addr" }),
    el({ autocomplete: "tel", name: "ph" }),
  ]);
  assert.equal(got.given.name, "fn");
  assert.equal(got.family.name, "ln");
  assert.equal(got.address.name, "addr");
  assert.equal(got.phone.name, "ph");
  assert.equal(got.number, null);
  assert.equal(
    isFillTarget(el({ tagName: "INPUT", autocomplete: "cc-number" })),
    true,
  );
});
