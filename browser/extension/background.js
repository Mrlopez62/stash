// stash: the extension's background script. It owns the connection to the
// native host (`stash native-host`), and carries out fills the popup asks
// for, so a fill finishes even if the popup closes while Touch ID is up.
//
// It never stores values: each fill's values are passed straight into the
// page and dropped.

"use strict";

const HOST = "dev.stash.autofill";

let port = null;
let nextId = 1;
const pending = new Map();
let popupOpen = false;

function connect() {
  port = chrome.runtime.connectNative(HOST);
  port.onMessage.addListener((message) => {
    const waiter = pending.get(message.id);
    if (waiter) {
      pending.delete(message.id);
      waiter(message);
    }
  });
  port.onDisconnect.addListener(() => {
    const why = chrome.runtime.lastError?.message || "stash disconnected";
    const error = /not found|not exist|forbidden|specified native/i.test(why) ? "not-installed" : why;
    for (const waiter of pending.values()) waiter({ ok: false, error });
    pending.clear();
    port = null;
  });
}

/// One request to the native host.
function ask(request) {
  if (!port) connect();
  const id = nextId++;
  return new Promise((resolve) => {
    pending.set(id, resolve);
    try {
      port.postMessage({ ...request, id });
    } catch (e) {
      pending.delete(id);
      resolve({ ok: false, error: "not-installed" });
    }
  });
}

/// The page in a tab. The popup's activeTab grant lets us read it.
async function pageOf(tabId) {
  const tab = await chrome.tabs.get(tabId);
  if (!tab.url) throw new Error("stash can't read this tab");
  return tab.url;
}

async function fill(tabId, name, kind) {
  const url = await pageOf(tabId);
  const expectedOrigin = new URL(url).origin;
  const values = await ask({ type: "fill", url, name, kind });
  if (!values.ok) return values;
  // The page may have changed while Touch ID was up: fill only the page
  // the vault approved.
  if (new URL(await pageOf(tabId)).origin !== expectedOrigin) {
    return { ok: false, error: "The page changed before stash could fill it." };
  }
  const mode = values.kind;
  // Load the fill code, ask each frame whether it may be filled, and send
  // the values only to the frames that may (see fill.js).
  const everywhere = { tabId, allFrames: true };
  await chrome.scripting.executeScript({ target: everywhere, files: ["fill.js"] });
  const checks = await chrome.scripting.executeScript({
    target: everywhere,
    func: (args) => globalThis.__stashCheck(args),
    args: [{ expectedOrigin, mode }],
  });
  const frameIds = checks.filter((r) => r.result === true).map((r) => r.frameId);
  if (!frameIds.length) return { ok: true, filled: [] };
  const results = await chrome.scripting.executeScript({
    target: { tabId, frameIds },
    func: (args) => globalThis.__stashFill(args),
    args: [{ expectedOrigin, mode, values }],
  });
  const filled = results.flatMap((r) => r.result?.filled || []);
  return { ok: true, filled };
}

async function handle(message) {
  switch (message.type) {
    case "suggest":
      return ask({ type: "suggest", url: await pageOf(message.tabId) });
    case "unlock": {
      const reply = await ask({ type: "unlock", url: await pageOf(message.tabId) });
      // Touch ID usually takes focus and closes the popup; bring it back.
      if (reply.ok && !popupOpen) chrome.action.openPopup?.().catch(() => {});
      return reply;
    }
    case "fill":
      return fill(message.tabId, message.name, message.kind);
    case "lock":
      return ask({ type: "lock" });
    default:
      return { ok: false, error: "unknown request" };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Only our own popup talks to us; pages and other extensions can't.
  if (sender.id !== chrome.runtime.id || !sender.url?.startsWith(chrome.runtime.getURL("popup.html"))) {
    return false;
  }
  handle(message)
    .then(sendResponse)
    .catch((e) => sendResponse({ ok: false, error: String(e.message || e) }));
  return true;
});

chrome.runtime.onConnect.addListener((p) => {
  if (p.name !== "popup" || p.sender?.id !== chrome.runtime.id) return;
  popupOpen = true;
  p.onDisconnect.addListener(() => {
    popupOpen = false;
  });
});
