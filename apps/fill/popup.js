const root = document.getElementById("root");

function show(html) {
  root.innerHTML = html;
}

function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
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

function saveButton(got) {
  const b = document.createElement("button");
  const name = document.createElement("div");
  name.className = "name";
  name.textContent = "Save this sign-in";
  b.appendChild(name);
  b.addEventListener("click", function () {
    chrome.runtime.sendMessage(
      {
        type: "popup-save",
        tabId: got.tabId,
        url: got.url,
      },
      function (res) {
        if (res && res.ok) {
          window.close();
          return;
        }
        show('<div class="err">Save canceled or failed.</div>');
      },
    );
  });
  return b;
}

chrome.runtime.sendMessage({ type: "popup-list" }, function (got) {
  if (chrome.runtime.lastError) {
    show('<div class="err">Host is not running. veil fill install</div>');
    return;
  }
  const entries = (got && got.entries) || [];
  const logins = entries.filter(function (e) {
    return e.kind === "login";
  });
  root.textContent = "";
  const host = hostOf((got && got.url) || "");
  if (host) {
    const where = document.createElement("div");
    where.className = "login";
    where.textContent = host;
    root.appendChild(where);
  }
  const offerSave = !!(got && got.canSave && !logins.length);
  if (!entries.length && !(got && got.canGenerate) && !offerSave) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "Nothing saved for this site.";
    root.appendChild(empty);
    return;
  }
  if (offerSave) {
    root.appendChild(saveButton(got));
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
      chrome.tabs.query({}, function (tabs) {
        const tab = globalThis.veilTab.tabByURL(tabs, got.url);
        chrome.runtime.sendMessage(
          { type: "popup-fill", uuid: e.uuid, url: got.url, tabId: tab && tab.id },
          function (res) {
            if (res && res.ok) {
              window.close();
              return;
            }
            show('<div class="err">Fill canceled or failed.</div>');
          },
        );
      });
    });
    root.appendChild(b);
  });
  if (got && got.canGenerate) {
    root.appendChild(suggestButton(got));
  }
});
