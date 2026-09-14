const root = document.getElementById("root");

function show(html) {
  root.innerHTML = html;
}

function suggestButton(got) {
  const b = document.createElement("button");
  const name = document.createElement("div");
  name.className = "name";
  name.textContent = "Suggest a password";
  b.appendChild(name);
  b.addEventListener("click", function () {
    chrome.runtime.sendMessage(
      {
        type: "popup-generate",
        tabId: got.tabId,
        url: got.url,
        login: got.login || "",
        passwordRules: got.passwordRules || "",
      },
      function (res) {
        if (res && res.ok) {
          window.close();
          return;
        }
        show('<div class="err">Generate canceled or failed.</div>');
      },
    );
  });
  return b;
}

chrome.runtime.sendMessage({ type: "popup-list" }, function (got) {
  if (chrome.runtime.lastError) {
    show('<div class="err">Host is not running. password-manager fill install</div>');
    return;
  }
  const entries = (got && got.entries) || [];
  root.textContent = "";
  if (!entries.length && !(got && got.canGenerate)) {
    show('<div class="empty">Nothing saved for this site.</div>');
    return;
  }
  entries.forEach(function (e) {
    const b = document.createElement("button");
    const name = document.createElement("div");
    name.className = "name";
    name.textContent = e.name || e.uuid || "item";
    b.appendChild(name);
    if (e.login) {
      const login = document.createElement("div");
      login.className = "login";
      login.textContent = e.login;
      b.appendChild(login);
    } else if (e.kind && e.kind !== "login") {
      const kind = document.createElement("div");
      kind.className = "login";
      kind.textContent = e.kind;
      b.appendChild(kind);
    }
    b.addEventListener("click", function () {
      chrome.runtime.sendMessage(
        { type: "popup-fill", tabId: got.tabId, url: got.url, uuid: e.uuid },
        function (res) {
          if (res && res.ok) {
            window.close();
            return;
          }
          show('<div class="err">Fill canceled or failed.</div>');
        },
      );
    });
    root.appendChild(b);
  });
  if (got && got.canGenerate) {
    root.appendChild(suggestButton(got));
  }
});
