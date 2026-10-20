// Tests for the background script's save flow (extension/background.js),
// run against a fake `chrome` API: `node --test browser/test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const SOURCE = readFileSync(new URL("../extension/background.js", import.meta.url), "utf8");
const EXT = "chrome-extension://ext/";

/// A fresh background script with a fake browser around it. `host` answers
/// native-messaging requests; everything the script does is recorded.
function load(host, tabUrl = "https://shop.example/checkout") {
  const listeners = {};
  const toHost = [];
  const toTabs = [];
  const port = {
    onMessage: { addListener: (fn) => (port.reply = fn) },
    onDisconnect: { addListener() {} },
    postMessage(message) {
      toHost.push(message);
      Promise.resolve().then(() => port.reply({ id: message.id, ...host(message) }));
    },
  };
  const event = (name) => ({ addListener: (fn) => (listeners[name] = fn) });
  const chrome = {
    runtime: {
      id: "ext",
      getURL: (p) => EXT + p,
      connectNative: () => port,
      onMessage: event("message"),
      onConnect: event("connect"),
      onStartup: event("startup"),
      onInstalled: event("installed"),
    },
    permissions: { contains: async () => false, onAdded: event("added"), onRemoved: event("removed") },
    scripting: {
      getRegisteredContentScripts: async () => [],
      registerContentScripts: async () => {},
      unregisterContentScripts: async () => {},
      executeScript: async () => [],
    },
    tabs: {
      get: async () => ({ url: tabUrl }),
      sendMessage: async (tabId, message) => {
        toTabs.push({ tabId, message });
      },
      onUpdated: event("updated"),
      onRemoved: event("removed-tab"),
    },
    action: { openPopup: async () => {} },
  };
  vm.runInNewContext(SOURCE, { chrome, crypto: globalThis.crypto, setTimeout, URL, console });
  /// Send a message as `sender` would; resolves with the reply, or
  /// `undefined` if the background ignored it.
  const send = (message, sender) =>
    new Promise((resolve) => {
      const handled = listeners.message(message, { id: "ext", ...sender }, resolve);
      if (!handled) resolve(undefined);
    });
  const settle = () => new Promise((r) => setTimeout(r, 10));
  return { send, settle, toHost, toTabs };
}

const page = { url: "https://shop.example/checkout", tab: { id: 1 } };
const card = { number: "5555555555554444", cardholder: "Samus Aran", exp_month: "03", exp_year: "2028", cvv: "321", postal_code: "" };

function cardHost(message) {
  if (message.type === "check_card") return { ok: true, state: "new", host: "shop.example", summary: "Mastercard •••• 4444 · 03/28" };
  if (message.type === "save_card") return { ok: true, name: "cards/mastercard-4444", action: "created" };
  return { ok: false, error: "unexpected" };
}

test("a submitted card is offered once, and saved only from stash's own prompt", async () => {
  const b = load(cardHost);
  await b.send({ type: "captured-card", card }, page);
  await b.settle();
  assert.deepEqual(b.toHost.map((m) => m.type), ["check_card"]);
  const show = b.toTabs.find((t) => t.message.type === "stash-show-save");
  assert.ok(show, "the save prompt was shown");
  const prompt = { url: `${EXT}save.html#${show.message.token}`, tab: { id: 1 } };

  // The prompt learns only the summary, never the number or code.
  const info = await b.send({ type: "save-info", token: show.message.token }, prompt);
  assert.deepEqual(JSON.parse(JSON.stringify(info)), { ok: true, kind: "card", host: "shop.example", summary: "Mastercard •••• 4444 · 03/28", state: "new" });

  const saved = await b.send({ type: "save-confirm", token: show.message.token }, prompt);
  assert.equal(saved.name, "cards/mastercard-4444");
  const request = b.toHost.find((m) => m.type === "save_card");
  assert.equal(request.number, "5555555555554444");
  assert.equal(request.cvv, "321");
  assert.equal(request.url, page.url);
  // Once saved, it's gone from memory: the token no longer works.
  assert.equal((await b.send({ type: "save-info", token: show.message.token }, prompt)).ok, false);
});

test("the prompt must know the token and be in the same tab", async () => {
  const b = load(cardHost);
  await b.send({ type: "captured-card", card }, page);
  await b.settle();
  const token = b.toTabs.find((t) => t.message.type === "stash-show-save").message.token;
  const wrongToken = await b.send({ type: "save-confirm", token: "nope" }, { url: `${EXT}save.html#nope`, tab: { id: 1 } });
  assert.equal(wrongToken.ok, false);
  const otherTab = await b.send({ type: "save-confirm", token }, { url: `${EXT}save.html#${token}`, tab: { id: 2 } });
  assert.equal(otherTab.ok, false);
  assert.ok(!b.toHost.some((m) => m.type === "save_card"), "nothing was saved");
});

test("cards already saved, or with a bad number, aren't offered", async () => {
  for (const state of ["saved", "invalid"]) {
    const b = load((m) => (m.type === "check_card" ? { ok: true, state, host: "shop.example" } : { ok: false }));
    await b.send({ type: "captured-card", card }, page);
    await b.settle();
    assert.ok(!b.toTabs.some((t) => t.message.type === "stash-show-save"), state);
  }
});

test("a card from another site's frame is ignored without asking the vault", async () => {
  const b = load(cardHost);
  const reply = await b.send({ type: "captured-card", card }, { url: "https://ads.example/frame", tab: { id: 1 } });
  assert.equal(reply.ok, false);
  assert.equal(b.toHost.length, 0);
});

test("a page can't ask for anything but offering to save", async () => {
  const b = load(cardHost);
  for (const type of ["fill", "suggest", "unlock", "lock", "save-confirm"]) {
    assert.equal(await b.send({ type, name: "cards/visa", tabId: 1 }, page), undefined, type);
  }
  assert.equal(b.toHost.length, 0);
});

test("a dismissed card is dropped from memory", async () => {
  const b = load(cardHost);
  await b.send({ type: "captured-card", card }, page);
  await b.settle();
  const token = b.toTabs.find((t) => t.message.type === "stash-show-save").message.token;
  const prompt = { url: `${EXT}save.html#${token}`, tab: { id: 1 } };
  await b.send({ type: "save-dismiss", token }, prompt);
  assert.equal((await b.send({ type: "save-info", token }, prompt)).ok, false);
});
