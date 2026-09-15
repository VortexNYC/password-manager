const { test } = require("node:test");
const assert = require("node:assert/strict");
const { usable, tabByURL } = require("./tab.js");

test("usable is http(s) only", () => {
  assert.equal(usable("http://127.0.0.1:8765/stripe-test-checkout.html"), true);
  assert.equal(usable("https://veil.nyc"), true);
  assert.equal(usable("chrome://extensions"), false);
  assert.equal(usable("chrome-extension://abc/popup.html"), false);
  assert.equal(usable(""), false);
});

test("tabByURL matches the chooser URL, not the popup or a search tab", () => {
  const checkout = "http://127.0.0.1:8765/stripe-test-checkout.html";
  const tabs = [
    { id: 1, url: "chrome-extension://abc/popup.html" },
    { id: 2, url: checkout },
    { id: 3, url: "https://www.google.com/search?q=" + checkout },
  ];
  const hit = tabByURL(tabs, checkout);
  assert.equal(hit && hit.id, 2);
  assert.equal(tabByURL(tabs, ""), null);
  assert.equal(tabByURL(tabs, "chrome://extensions"), null);
});
