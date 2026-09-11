(function () {
  chrome.runtime.onMessage.addListener(function (msg, _sender, sendResponse) {
    if (!msg || msg.type !== "write") {
      return;
    }
    try {
      veilFields.writeLogin(document, {
        login: msg.login || "",
        password: msg.password || "",
        totp: msg.totp || "",
      });
      sendResponse({ ok: true });
    } catch (err) {
      sendResponse({ ok: false });
    }
    return true;
  });

  document.addEventListener(
    "focusin",
    function (ev) {
      if (!ev.isTrusted || !veilFields.isFillTarget(ev.target)) {
        return;
      }
      chrome.runtime.sendMessage({ type: "trusted-focus" });
    },
    true,
  );
})();
