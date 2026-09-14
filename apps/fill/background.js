const HOST = "nyc.veil.fill";
const LOGIN = "https://login.veil.nyc";

let port = null;
const waiters = [];
const matches = new Map();
let openedLogin = false;

function usable(url) {
  return typeof url === "string" && (url.startsWith("https://") || url.startsWith("http://"));
}

function pageOrigin(url) {
  try {
    return new URL(url).origin;
  } catch (_err) {
    return "";
  }
}

function connect() {
  if (port) {
    return;
  }
  port = chrome.runtime.connectNative(HOST);
  port.onMessage.addListener(function (msg) {
    const w = waiters.shift();
    if (w) {
      w.resolve(msg || {});
    }
  });
  port.onDisconnect.addListener(function () {
    port = null;
    const err = chrome.runtime.lastError && chrome.runtime.lastError.message;
    while (waiters.length) {
      waiters.shift().reject(new Error(err || "host gone"));
    }
  });
}

function hostSend(msg, timeoutMs) {
  connect();
  const ms = timeoutMs || 8000;
  return new Promise(function (resolve, reject) {
    if (!port) {
      reject(new Error("no host"));
      return;
    }
    let done = false;
    const finish = function (fn, v) {
      if (done) {
        return;
      }
      done = true;
      clearTimeout(timer);
      fn(v);
    };
    const wait = {
      resolve: function (v) {
        finish(resolve, v);
      },
      reject: function (e) {
        finish(reject, e);
      },
    };
    const timer = setTimeout(function () {
      const i = waiters.indexOf(wait);
      if (i >= 0) {
        waiters.splice(i, 1);
      }
      wait.reject(new Error("host timeout"));
    }, ms);
    waiters.push(wait);
    try {
      port.postMessage(msg);
    } catch (err) {
      waiters.pop();
      wait.reject(err);
    }
  });
}

function needLogin(msg) {
  return msg && msg.error === "need_login";
}

function openLogin() {
  if (openedLogin) {
    return;
  }
  openedLogin = true;
  chrome.tabs.create({ url: LOGIN });
}

async function ping() {
  const msg = await hostSend({ action: "ping" });
  if (needLogin(msg)) {
    openLogin();
  }
  return msg;
}

async function matchTab(tabId, url) {
  if (!usable(url)) {
    matches.delete(tabId);
    await badge(tabId, 0);
    return [];
  }
  const msg = await hostSend({ action: "match", url: url });
  const entries = (msg && msg.entries) || [];
  matches.set(tabId, { url: url, entries: entries });
  await badge(tabId, entries.length);
  return entries;
}

async function badge(tabId, n) {
  const text = n > 0 ? String(n) : "";
  try {
    await chrome.action.setBadgeText({ tabId: tabId, text: text });
  } catch (_err) {
    /* tab gone */
  }
}

async function writeTab(tabId, entry) {
  const payload = {
    type: "write",
    login: entry.login || "",
    password: entry.password || "",
    totp: entry.totp || "",
  };
  try {
    try {
      await chrome.tabs.sendMessage(tabId, payload);
    } catch (_err) {
      await chrome.scripting.executeScript({ target: { tabId: tabId }, files: ["fields.js"] });
      await chrome.scripting.executeScript({
        target: { tabId: tabId },
        args: [{ login: payload.login, password: payload.password, totp: payload.totp }],
        func: function (got) {
          globalThis.veilFields.writeLogin(document, got);
        },
      });
    }
  } finally {
    entry.login = "";
    entry.password = "";
    entry.totp = "";
  }
}

async function fillTab(tabId, url, uuid) {
  const body = { action: "fill", url: url };
  if (uuid) {
    body.uuid = uuid;
  }
  const msg = await hostSend(body, 90000);
  if (needLogin(msg)) {
    openLogin();
    return { ok: false, error: "need_login" };
  }
  const entries = (msg && msg.entries) || [];
  if (!entries.length) {
    return { ok: false, error: "empty" };
  }
  await writeTab(tabId, entries[0]);
  return { ok: true };
}

async function executeTab(tabId, url) {
  let hit = matches.get(tabId);
  if (!hit || hit.url !== url) {
    await matchTab(tabId, url);
    hit = matches.get(tabId);
  }
  const entries = (hit && hit.entries) || [];
  if (entries.length !== 1 || entries[0].kind !== "login" || entries[0].affiliated) {
    return { ok: false, error: "choose", entries: entries };
  }
  return fillTab(tabId, url, entries[0].uuid);
}

async function activeTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0] || null;
}

chrome.runtime.onInstalled.addListener(function () {
  ping().catch(function () {});
});
chrome.runtime.onStartup.addListener(function () {
  ping().catch(function () {});
});

chrome.tabs.onUpdated.addListener(function (tabId, info, tab) {
  const url = tab && (tab.url || tab.pendingUrl);
  if (info.status !== "complete" || !usable(url)) {
    return;
  }
  matchTab(tabId, url).catch(function () {});
});

chrome.tabs.onActivated.addListener(function (info) {
  chrome.tabs.get(info.tabId, function (tab) {
    const url = tab && (tab.url || tab.pendingUrl);
    if (chrome.runtime.lastError || !usable(url)) {
      return;
    }
    matchTab(tab.id, url).catch(function () {});
  });
});

chrome.tabs.onRemoved.addListener(function (tabId) {
  matches.delete(tabId);
});

chrome.commands.onCommand.addListener(function (command) {
  if (command !== "fill") {
    return;
  }
  activeTab().then(function (tab) {
    if (!tab || !usable(tab.url)) {
      return;
    }
    executeTab(tab.id, tab.url).then(function (got) {
      if (got && got.error === "choose") {
        chrome.action.openPopup().catch(function () {});
      }
    });
  });
});

chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (!msg || !msg.type) {
    return;
  }
  if (msg.type === "trusted-focus") {
    const tab = sender.tab;
    const url = tab && (tab.url || tab.pendingUrl);
    if (!tab || !usable(url)) {
      return;
    }
    executeTab(tab.id, url).then(function (got) {
      if (got && got.error === "choose") {
        chrome.action.openPopup().catch(function () {});
      }
    }, function () {});
    return;
  }
  if (msg.type === "popup-list") {
    activeTab().then(function (tab) {
      if (!tab || !usable(tab.url)) {
        sendResponse({ entries: [], url: "" });
        return;
      }
      matchTab(tab.id, tab.url).then(function (entries) {
        sendResponse({ entries: entries, url: tab.url, tabId: tab.id });
      });
    });
    return true;
  }
  if (msg.type === "popup-fill") {
    fillTab(msg.tabId, msg.url, msg.uuid).then(function (got) {
      sendResponse(got);
    });
    return true;
  }
  if (msg.type === "passkeyCreate" || msg.type === "passkeyGet") {
    const tab = sender.tab;
    const url = tab && (tab.url || tab.pendingUrl);
    if (!tab || !usable(url) || msg.origin !== pageOrigin(url)) {
      sendResponse({ error: "failed" });
      return true;
    }
    const req = {
      action: msg.type,
      origin: msg.origin,
      publicKey: msg.publicKey,
    };
    if (msg.type === "passkeyCreate" && msg.relatedOrigins) {
      req.relatedOrigins = msg.relatedOrigins;
    }
    hostSend(req, 90000).then(
      function (got) {
        sendResponse(got || { error: "failed" });
      },
      function () {
        sendResponse({ error: "failed" });
      },
    );
    return true;
  }
});
