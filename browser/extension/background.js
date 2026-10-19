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

/// executeScript, tried once more if a frame was going away (like the
/// stash menu's own frame, just closed).
async function inject(details) {
  try {
    return await chrome.scripting.executeScript(details);
  } catch {
    await new Promise((r) => setTimeout(r, 150));
    return chrome.scripting.executeScript(details);
  }
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
  await inject({ target: everywhere, files: ["fill.js"] });
  const checks = await inject({
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

/// Requests from the toolbar popup or the in-page menu. `tabId` is the tab
/// the popup was opened on, or the tab the menu's frame is in.
async function handle(message, tabId, fromMenu) {
  switch (message.type) {
    case "suggest":
      return ask({ type: "suggest", url: await pageOf(tabId) });
    case "unlock": {
      const reply = await ask({ type: "unlock", url: await pageOf(tabId) });
      // Touch ID usually takes focus and closes the popup; bring it back.
      if (reply.ok && !fromMenu && !popupOpen) chrome.action.openPopup?.().catch(() => {});
      return reply;
    }
    case "fill":
      // The menu's own frame closes first, so only the page is filled.
      if (fromMenu) await closeMenu(tabId);
      return fill(tabId, message.name, message.kind);
    case "lock":
      return ask({ type: "lock" });
    case "close-menu":
      await closeMenu(tabId);
      return { ok: true };
    default:
      return { ok: false, error: "unknown request" };
  }
}

function closeMenu(tabId) {
  return chrome.tabs.sendMessage(tabId, { type: "stash-close-menu" }).catch(() => {});
}

/// Who sent a message: our popup, our menu or save prompt (frames of
/// ours inside a tab), our in-page script, or nobody we answer.
function senderKind(sender) {
  if (sender.id !== chrome.runtime.id) return null;
  const ours = (page) => sender.url?.startsWith(chrome.runtime.getURL(page));
  if (ours("popup.html")) return "popup";
  if (ours("menu.html") && sender.tab) return "menu";
  if (ours("save.html") && sender.tab) return "save";
  if (sender.tab && /^https?:/.test(sender.url || "")) return "page";
  return null;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const kind = senderKind(sender);
  let work;
  if (kind === "popup") work = handle(message, message.tabId, false);
  else if (kind === "menu") work = handle(message, sender.tab.id, true);
  else if (kind === "save") work = handleSave(message, sender);
  // The in-page script may only report a sign-in to offer saving.
  else if (kind === "page" && message.type === "captured") work = captured(message, sender);
  else if (kind === "page" && message.type === "captured-card") work = capturedCard(message.card, sender);
  else return false;
  work
    .then(sendResponse)
    .catch((e) => sendResponse({ ok: false, error: String(e.message || e) }));
  return true;
});

// ---- stash in sign-in fields (opt-in) ----

const INLINE_ORIGINS = ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"];
const INLINE_SCRIPT = "stash-inline";

/// Run the in-page script exactly when the user has granted site access
/// (Settings → "Show stash in sign-in fields").
async function syncInline() {
  const on = await chrome.permissions.contains({ origins: INLINE_ORIGINS });
  const registered = await chrome.scripting.getRegisteredContentScripts({ ids: [INLINE_SCRIPT] });
  if (on && !registered.length) {
    await chrome.scripting.registerContentScripts([
      { id: INLINE_SCRIPT, matches: INLINE_ORIGINS, js: ["fill.js", "inline.js"], allFrames: true, runAt: "document_idle" },
    ]);
  } else if (!on && registered.length) {
    await chrome.scripting.unregisterContentScripts({ ids: [INLINE_SCRIPT] });
  }
}

chrome.permissions.onAdded.addListener(() => syncInline().catch(() => {}));
chrome.permissions.onRemoved.addListener(() => syncInline().catch(() => {}));
chrome.runtime.onStartup?.addListener(() => syncInline().catch(() => {}));
chrome.runtime.onInstalled.addListener(() => syncInline().catch(() => {}));

// ---- Offering to save logins ----

/// Sign-ins waiting for a "save?" answer, by tab. Held in memory only, and
/// dropped after a few minutes or once answered.
const pendingSaves = new Map();
const SAVE_TIMEOUT = 3 * 60 * 1000;
/// A card's number and security code wait in memory for less time.
const CARD_SAVE_TIMEOUT = 60 * 1000;

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function captured(message, sender) {
  const tabId = sender.tab.id;
  const url = sender.url;
  // Only a form in the page itself (or a same-origin frame), never another
  // site's frame inside it.
  const top = await pageOf(tabId).catch(() => null);
  if (!top || new URL(top).origin !== new URL(url).origin) return { ok: false };
  if (typeof message.password !== "string" || !message.password) return { ok: false };
  const username = typeof message.username === "string" ? message.username : "";
  const check = await ask({ type: "check_saved", url, username, password: message.password });
  if (!check.ok || check.state === "same") return { ok: true };
  const token = randomToken();
  pendingSaves.set(tabId, { token, url, host: check.host, username, password: message.password, state: check.state, at: Date.now() });
  setTimeout(() => {
    const pending = pendingSaves.get(tabId);
    if (pending?.token === token) dismissSave(tabId);
  }, SAVE_TIMEOUT);
  // Show it now (single-page apps) and again once the next page loads.
  showSave(tabId);
  return { ok: true };
}

/// A card from a submitted checkout: offer to save it if it's new.
async function capturedCard(card, sender) {
  const tabId = sender.tab.id;
  const url = sender.url;
  const top = await pageOf(tabId).catch(() => null);
  if (!top || new URL(top).origin !== new URL(url).origin) return { ok: false };
  if (!card || typeof card.number !== "string") return { ok: false };
  const fields = {
    number: card.number,
    cardholder: String(card.cardholder || ""),
    exp_month: String(card.exp_month || ""),
    exp_year: String(card.exp_year || ""),
    cvv: String(card.cvv || ""),
    postal_code: String(card.postal_code || ""),
  };
  const check = await ask({ type: "check_card", url, number: fields.number, exp_month: fields.exp_month, exp_year: fields.exp_year });
  if (!check.ok || check.state === "saved" || check.state === "invalid") return { ok: true };
  const token = randomToken();
  pendingSaves.set(tabId, { kind: "card", token, url, host: check.host, summary: check.summary, card: fields, state: "new", at: Date.now() });
  setTimeout(() => {
    const pending = pendingSaves.get(tabId);
    if (pending?.token === token) dismissSave(tabId);
  }, CARD_SAVE_TIMEOUT);
  showSave(tabId);
  return { ok: true };
}

function showSave(tabId) {
  const pending = pendingSaves.get(tabId);
  if (!pending) return;
  chrome.tabs.sendMessage(tabId, { type: "stash-show-save", token: pending.token }, { frameId: 0 }).catch(() => {});
}

function dismissSave(tabId) {
  pendingSaves.delete(tabId);
  chrome.tabs.sendMessage(tabId, { type: "stash-hide-save" }, { frameId: 0 }).catch(() => {});
}

chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "complete" && pendingSaves.has(tabId)) showSave(tabId);
});
chrome.tabs.onRemoved.addListener((tabId) => pendingSaves.delete(tabId));

/// The save prompt's requests. It must be in the tab whose sign-in it's
/// asking about, and know that sign-in's token.
async function handleSave(message, sender) {
  const tabId = sender.tab.id;
  const pending = pendingSaves.get(tabId);
  if (!pending || pending.token !== message.token) return { ok: false, error: "nothing to save" };
  switch (message.type) {
    case "save-info":
      return pending.kind === "card"
        ? { ok: true, kind: "card", host: pending.host, summary: pending.summary, state: pending.state }
        : { ok: true, kind: "login", host: pending.host, username: pending.username, state: pending.state };
    case "save-confirm": {
      const reply = pending.kind === "card"
        ? await ask({ type: "save_card", url: pending.url, ...pending.card })
        : await ask({ type: "save_login", url: pending.url, username: pending.username, password: pending.password });
      if (reply.ok) pendingSaves.delete(tabId);
      return reply;
    }
    case "save-dismiss":
      dismissSave(tabId);
      return { ok: true };
    default:
      return { ok: false, error: "unknown request" };
  }
}

chrome.runtime.onConnect.addListener((p) => {
  if (p.name !== "popup" || p.sender?.id !== chrome.runtime.id) return;
  popupOpen = true;
  p.onDisconnect.addListener(() => {
    popupOpen = false;
  });
});

syncInline().catch(() => {});
