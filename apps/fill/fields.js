// Field pick + write. WHATWG autocomplete first. No site catalog.
(function (root) {
  function fieldToken(s) {
    const skip = {
      on: true,
      off: true,
      shipping: true,
      billing: true,
      home: true,
      work: true,
      mobile: true,
      fax: true,
      pager: true,
    };
    const parts = String(s || "")
      .toLowerCase()
      .trim()
      .split(/\s+/);
    for (let i = parts.length - 1; i >= 0; i--) {
      const p = parts[i];
      if (!p || skip[p] || p.indexOf("section-") === 0) {
        continue;
      }
      return p;
    }
    return "";
  }
  function auto(el) {
    if (!el) {
      return "";
    }
    const tokens = [el.autocomplete];
    if (typeof el.getAttribute === "function") {
      tokens.push(el.getAttribute("autocomplete"), el.getAttribute("data-autocomplete"));
    }
    for (let i = 0; i < tokens.length; i++) {
      const s = fieldToken(tokens[i]);
      if (s) {
        return s;
      }
    }
    return "";
  }
  function typ(el) {
    return String(el.type || "text").toLowerCase();
  }
  function ident(el) {
    return String(el.name || el.id || "");
  }
  function visible(el) {
    if (el.hidden || el.disabled) {
      return false;
    }
    if (typeof el.offsetParent === "undefined") {
      return true;
    }
    return el.offsetParent !== null || typ(el) === "password";
  }

  function pickFields(els) {
    const live = (els || []).filter(visible);
    const byAuto = function (names) {
      return live.find(function (el) {
        return names.indexOf(auto(el)) !== -1;
      });
    };
    const username =
      byAuto(["username", "email"]) ||
      live.find(function (el) {
        return typ(el) === "email";
      }) ||
      live.find(function (el) {
        return /user|email|login/i.test(ident(el)) && typ(el) !== "password";
      }) ||
      null;
    const current =
      byAuto(["current-password"]) ||
      live.find(function (el) {
        return typ(el) === "password" && auto(el) !== "new-password";
      }) ||
      null;
    const newPassword = live.filter(function (el) {
      return auto(el) === "new-password";
    });
    const totp =
      byAuto(["one-time-code"]) ||
      live.find(function (el) {
        return /otp|totp|one-time|2fa/i.test(ident(el) + " " + auto(el));
      }) ||
      null;
    const number =
      byAuto(["cc-number"]) ||
      live.find(function (el) {
        return /card.?number|cc-num/i.test(ident(el) + " " + auto(el));
      }) ||
      null;
    const expMonth = byAuto(["cc-exp-month"]);
    const expYear = byAuto(["cc-exp-year"]);
    const exp = byAuto(["cc-exp"]);
    const cvv = byAuto(["cc-csc", "cc-cvc"]);
    const given = byAuto(["given-name", "cc-given-name"]);
    const family = byAuto(["family-name", "cc-family-name"]);
    const name = byAuto(["cc-name", "name"]);
    const address = byAuto(["street-address", "address-line1"]);
    const city = byAuto(["address-level2"]);
    const region = byAuto(["address-level1"]);
    const postal = byAuto(["postal-code"]);
    const country = byAuto(["country", "country-name"]);
    const phone = byAuto(["tel", "tel-national"]);
    return {
      username: username || null,
      password: current || null,
      newPassword: newPassword,
      totp: totp || null,
      number: number || null,
      expMonth: expMonth || null,
      expYear: expYear || null,
      exp: exp || null,
      cvv: cvv || null,
      given: given || null,
      family: family || null,
      name: name || null,
      address: address || null,
      city: city || null,
      region: region || null,
      postal: postal || null,
      country: country || null,
      phone: phone || null,
    };
  }

  function nativeSet(el, value) {
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const desc = Object.getOwnPropertyDescriptor(proto, "value");
    if (desc && desc.set) {
      desc.set.call(el, value);
    } else {
      el.value = value;
    }
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function writeField(el, value) {
    if (!el || value == null || value === "") {
      return;
    }
    nativeSet(el, value);
  }

  function writeLogin(doc, entry) {
    const fields = pickFields(Array.prototype.slice.call(doc.querySelectorAll("input, textarea")));
    writeField(fields.username, entry.login);
    if (fields.newPassword && fields.newPassword.length) {
      fields.newPassword.forEach(function (el) {
        writeField(el, entry.password);
      });
    } else {
      writeField(fields.password, entry.password);
    }
    writeField(fields.totp, entry.totp);
  }

  function writeCard(doc, entry) {
    const fields = pickFields(Array.prototype.slice.call(doc.querySelectorAll("input, textarea")));
    writeField(fields.number, entry.number);
    writeField(fields.expMonth, entry.expMonth);
    writeField(fields.expYear, entry.expYear);
    if (fields.exp && entry.expMonth && entry.expYear) {
      writeField(fields.exp, entry.expMonth + "/" + String(entry.expYear).slice(-2));
    }
    writeField(fields.cvv, entry.cvv);
    writeField(fields.given, entry.givenName);
    writeField(fields.name, entry.givenName);
  }

  function writeIdentity(doc, entry) {
    const fields = pickFields(Array.prototype.slice.call(doc.querySelectorAll("input, textarea")));
    writeField(fields.given, entry.givenName);
    writeField(fields.family, entry.familyName);
    writeField(fields.address, entry.address);
    writeField(fields.city, entry.city);
    writeField(fields.region, entry.region);
    writeField(fields.postal, entry.postal);
    writeField(fields.country, entry.country);
    writeField(fields.phone, entry.phone);
    if (entry.givenName && entry.familyName) {
      writeField(fields.name, entry.givenName + " " + entry.familyName);
    }
  }

  function writeEntry(doc, entry) {
    if (!entry) {
      return;
    }
    if (entry.kind === "card") {
      writeCard(doc, entry);
      return;
    }
    if (entry.kind === "identity") {
      writeIdentity(doc, entry);
      return;
    }
    writeLogin(doc, entry);
  }

  function isFillTarget(el) {
    if (!el || (el.tagName !== "INPUT" && el.tagName !== "TEXTAREA")) {
      return false;
    }
    if (auto(el) === "new-password") {
      return true;
    }
    const t = typ(el);
    if (t === "password" || t === "email") {
      return true;
    }
    const a = auto(el);
    return (
      a === "username" ||
      a === "email" ||
      a === "current-password" ||
      a === "one-time-code" ||
      a.indexOf("cc-") === 0 ||
      a === "given-name" ||
      a === "family-name" ||
      a === "street-address" ||
      a === "address-line1" ||
      a === "address-level1" ||
      a === "address-level2" ||
      a === "postal-code" ||
      a === "country" ||
      a === "country-name" ||
      a === "tel" ||
      a === "tel-national" ||
      a === "name"
    );
  }

  root.veilFields = {
    auto: auto,
    pickFields: pickFields,
    writeField: writeField,
    writeLogin: writeLogin,
    writeCard: writeCard,
    writeIdentity: writeIdentity,
    writeEntry: writeEntry,
    isFillTarget: isFillTarget,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = root.veilFields;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
