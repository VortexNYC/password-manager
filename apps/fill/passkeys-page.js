// MAIN world. Intercept navigator.credentials. Content never talks to the host.
(function (root) {
  const SOURCE = "veil-fill";
  const REPLY = "veil-fill-reply";
  let seq = 0;
  const pending = Object.create(null);

  function b64url(buf) {
    const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function fromB64url(s) {
    const pad = String(s || "")
      .replace(/-/g, "+")
      .replace(/_/g, "/");
    const bin = atob(pad + "===".slice((pad.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out.buffer;
  }

  function jsonCopy(v) {
    if (v == null) {
      return v;
    }
    if (v instanceof ArrayBuffer) {
      return b64url(v);
    }
    if (ArrayBuffer.isView(v)) {
      return b64url(v);
    }
    if (Array.isArray(v)) {
      return v.map(jsonCopy);
    }
    if (typeof v === "object") {
      const o = {};
      Object.keys(v).forEach(function (k) {
        o[k] = jsonCopy(v[k]);
      });
      return o;
    }
    return v;
  }

  function credentialFromJSON(json) {
    if (!json || !json.id || !json.response) {
      throw new Error("veil passkey");
    }
    const rawId = fromB64url(json.rawId || json.id);
    const clientDataJSON = fromB64url(json.response.clientDataJSON);
    let response;
    if (json.response.attestationObject) {
      response = {
        clientDataJSON: clientDataJSON,
        attestationObject: fromB64url(json.response.attestationObject),
        getAuthenticatorData: function () {
          return json.response.authenticatorData ? fromB64url(json.response.authenticatorData) : new ArrayBuffer(0);
        },
        getPublicKey: function () {
          return json.response.publicKey ? fromB64url(json.response.publicKey) : null;
        },
        getPublicKeyAlgorithm: function () {
          return json.response.publicKeyAlgorithm || -7;
        },
        getTransports: function () {
          return ["internal"];
        },
      };
      if (typeof AuthenticatorAttestationResponse !== "undefined") {
        Object.setPrototypeOf(response, AuthenticatorAttestationResponse.prototype);
      }
    } else {
      response = {
        clientDataJSON: clientDataJSON,
        authenticatorData: fromB64url(json.response.authenticatorData),
        signature: fromB64url(json.response.signature),
        userHandle: json.response.userHandle ? fromB64url(json.response.userHandle) : null,
      };
      if (typeof AuthenticatorAssertionResponse !== "undefined") {
        Object.setPrototypeOf(response, AuthenticatorAssertionResponse.prototype);
      }
    }
    const cred = {
      id: json.id,
      rawId: rawId,
      type: "public-key",
      authenticatorAttachment: json.authenticatorAttachment || "platform",
      response: response,
      getClientExtensionResults: function () {
        return json.response.clientExtensionResults || {};
      },
    };
    if (typeof PublicKeyCredential !== "undefined") {
      Object.setPrototypeOf(cred, PublicKeyCredential.prototype);
    }
    return cred;
  }

  function ask(action, publicKey) {
    return new Promise(function (resolve, reject) {
      const id = String(++seq);
      pending[id] = { resolve: resolve, reject: reject };
      window.postMessage(
        {
          source: SOURCE,
          id: id,
          action: action,
          origin: location.origin,
          publicKey: jsonCopy(publicKey),
        },
        location.origin,
      );
    });
  }

  function install() {
    if (typeof window === "undefined" || window !== window.top) {
      return;
    }
    window.addEventListener("message", function (ev) {
      if (ev.source !== window || ev.origin !== location.origin || !ev.data || ev.data.source !== REPLY) {
        return;
      }
      const wait = pending[ev.data.id];
      if (!wait) {
        return;
      }
      delete pending[ev.data.id];
      const msg = ev.data.msg || {};
      if (msg.error || !msg.response) {
        wait.reject(new DOMException(msg.error || "NotAllowedError", "NotAllowedError"));
        return;
      }
      try {
        wait.resolve(credentialFromJSON(msg.response));
      } catch (err) {
        wait.reject(err);
      }
    });
    const creds = navigator.credentials;
    if (!creds || typeof creds.create !== "function") {
      return;
    }
    const origCreate = creds.create.bind(creds);
    const origGet = creds.get.bind(creds);
    creds.create = function (opts) {
      if (!opts || !opts.publicKey) {
        return origCreate(opts);
      }
      return ask("passkeyCreate", opts.publicKey);
    };
    creds.get = function (opts) {
      if (!opts || !opts.publicKey) {
        return origGet(opts);
      }
      return ask("passkeyGet", opts.publicKey);
    };
  }

  install();

  root.veilPasskeys = {
    b64url: b64url,
    fromB64url: fromB64url,
    jsonCopy: jsonCopy,
    credentialFromJSON: credentialFromJSON,
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = root.veilPasskeys;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
