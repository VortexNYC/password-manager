// Isolated world. Forwards MAIN-world passkey asks to the background. Never talks to origin.
(function () {
  if (window !== window.top) {
    return;
  }
  window.addEventListener("message", function (ev) {
    if (ev.source !== window || ev.origin !== location.origin || !ev.data || ev.data.source !== "veil-fill") {
      return;
    }
    const id = ev.data.id;
    chrome.runtime.sendMessage(
      {
        type: ev.data.action,
        origin: ev.data.origin,
        publicKey: ev.data.publicKey,
      },
      function (msg) {
        if (chrome.runtime.lastError) {
          window.postMessage({ source: "veil-fill-reply", id: id, msg: { error: "failed" } }, location.origin);
          return;
        }
        window.postMessage({ source: "veil-fill-reply", id: id, msg: msg || { error: "failed" } }, location.origin);
      },
    );
  });
})();
