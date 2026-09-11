const root = document.getElementById("root");

function show(html) {
  root.innerHTML = html;
}

chrome.runtime.sendMessage({ type: "popup-list" }, function (got) {
  if (chrome.runtime.lastError) {
    show('<div class="err">Host is not running. password-manager fill install</div>');
    return;
  }
  const entries = (got && got.entries) || [];
  if (!entries.length) {
    show('<div class="empty">Nothing saved for this site.</div>');
    return;
  }
  root.textContent = "";
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
});
