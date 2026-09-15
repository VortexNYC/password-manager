(function () {
  let lastOTPAuth = "";

  function probe(target) {
    const fields = veilFields.pickFields(Array.prototype.slice.call(document.querySelectorAll("input, textarea")));
    const el = target || document.activeElement;
    const login = fields.username && fields.username.value ? String(fields.username.value) : "";
    const rules =
      (el && el.getAttribute && (el.getAttribute("passwordrules") || el.getAttribute("passwordRules"))) || "";
    return {
      generate: !!(el && veilFields.auto(el) === "new-password"),
      canGenerate: !!(fields.newPassword && fields.newPassword.length),
      canSave: veilFields.canSave(fields, fields.password),
      login: login,
      passwordRules: rules,
    };
  }

  function typed() {
    const fields = veilFields.pickFields(Array.prototype.slice.call(document.querySelectorAll("input, textarea")));
    if (!veilFields.canSave(fields, fields.password)) {
      return { login: "", password: "" };
    }
    return {
      login: fields.username && fields.username.value ? String(fields.username.value) : "",
      password: String(fields.password.value),
    };
  }

  function reportOTPAuth(uri) {
    if (!uri || uri === lastOTPAuth) {
      return;
    }
    lastOTPAuth = uri;
    chrome.runtime.sendMessage({ type: "found-otpauth", otpauth: uri });
  }

  function scanOTPAuth(root) {
    const uri = veilFields.findOTPAuth(root || document);
    if (uri) {
      reportOTPAuth(uri);
    }
  }

  async function scanQR() {
    if (typeof BarcodeDetector === "undefined") {
      return;
    }
    let det;
    try {
      det = new BarcodeDetector({ formats: ["qr_code"] });
    } catch {
      return;
    }
    const imgs = document.images || [];
    for (let i = 0; i < imgs.length; i++) {
      try {
        const codes = await det.detect(imgs[i]);
        for (let j = 0; j < codes.length; j++) {
          const v = codes[j] && codes[j].rawValue ? String(codes[j].rawValue) : "";
          if (v.indexOf("otpauth://totp") === 0) {
            reportOTPAuth(v);
            return;
          }
        }
      } catch {
        /* image not readable */
      }
    }
  }

  chrome.runtime.onMessage.addListener(function (msg, _sender, sendResponse) {
    if (!msg || !msg.type) {
      return;
    }
    if (msg.type === "write") {
      try {
        sendResponse({ ok: !!veilFields.writeEntry(document, msg.entry || msg) });
      } catch {
        sendResponse({ ok: false });
      }
      return true;
    }
    if (msg.type === "probe") {
      sendResponse(probe());
      return true;
    }
    if (msg.type === "typed") {
      sendResponse(typed());
      return true;
    }
    if (msg.type === "otpauth") {
      sendResponse({ otpauth: lastOTPAuth || veilFields.findOTPAuth(document) || "" });
      return true;
    }
  });

  document.addEventListener(
    "focusin",
    function (ev) {
      if (!ev.isTrusted || !veilFields.isFillTarget(ev.target)) {
        return;
      }
      const ctx = probe(ev.target);
      chrome.runtime.sendMessage({
        type: "trusted-focus",
        generate: ctx.generate,
        login: ctx.login,
        passwordRules: ctx.passwordRules,
      });
    },
    true,
  );

  document.addEventListener(
    "submit",
    function (ev) {
      if (!ev.isTrusted) {
        return;
      }
      const got = typed();
      if (!got.password) {
        return;
      }
      chrome.runtime.sendMessage({ type: "offer-save", login: got.login, password: got.password });
    },
    true,
  );

  scanOTPAuth(document);
  scanQR();
  if (typeof MutationObserver === "function") {
    const obs = new MutationObserver(function (muts) {
      for (let i = 0; i < muts.length; i++) {
        const nodes = muts[i].addedNodes || [];
        for (let j = 0; j < nodes.length; j++) {
          if (nodes[j].nodeType === 1) {
            scanOTPAuth(nodes[j]);
          }
        }
      }
    });
    obs.observe(document.documentElement, { childList: true, subtree: true });
  }
})();
