// Field pick + write. WHATWG autocomplete first. No site catalog.
(function (root) {
  function auto(el) {
    if (!el) {
      return "";
    }
    const tokens = [el.autocomplete];
    if (typeof el.getAttribute === "function") {
      tokens.push(el.getAttribute("autocomplete"), el.getAttribute("data-autocomplete"));
    }
    for (let i = 0; i < tokens.length; i++) {
      const s = String(tokens[i] || "")
        .toLowerCase()
        .trim();
      if (s && s !== "on" && s !== "off") {
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
    return { username: username || null, password: current || null, newPassword: newPassword, totp: totp || null };
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
    return a === "username" || a === "email" || a === "current-password" || a === "one-time-code";
  }

  root.veilFields = {
    auto: auto,
    pickFields: pickFields,
    writeField: writeField,
    writeLogin: writeLogin,
    isFillTarget: isFillTarget,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = root.veilFields;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
