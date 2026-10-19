// stash: the popup. Shows logins saved for this site, plus cards and bank
// accounts, and asks the background script to fill the one you pick.

"use strict";

const main = document.getElementById("main");
const hostChip = document.getElementById("host");
const footer = document.getElementById("footer");
let tabId = null;
let rows = [];
let selected = 0;

// Lets the background know the popup is open (to reopen it after Touch ID).
chrome.runtime.connect({ name: "popup" });

const send = (message) => chrome.runtime.sendMessage({ ...message, tabId });

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const child of [].concat(children)) {
    if (child != null && child !== false) node.append(child);
  }
  return node;
}

function show(...nodes) {
  main.replaceChildren(...nodes);
}

function message(title, detail, action) {
  show(el("div", { class: "message" }, [el("p", { class: "title" }, title), detail && el("p", { class: "note" }, detail), action]));
  footer.hidden = true;
}

function errorText(error) {
  if (error === "not-installed") return null;
  if (error === "cancelled") return "Touch ID was cancelled.";
  return error;
}

function notInstalled() {
  message(
    "Connect stash to this browser",
    el("span", {}, ["Run ", el("code", {}, "stash browser install"), " in Terminal, then open stash again."]),
  );
}

async function load() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  tabId = tab?.id ?? null;
  if (tabId == null) return message("No page to fill");
  const reply = await send({ type: "suggest" });
  render(reply);
}

function render(reply) {
  if (!reply.ok) {
    if (reply.error === "not-installed") return notInstalled();
    return message("stash can't fill this page", errorText(reply.error));
  }
  hostChip.textContent = reply.host;
  hostChip.hidden = false;
  if (reply.locked) {
    const button = el("button", { class: "primary", type: "button", onclick: unlock }, "Unlock with Touch ID");
    message("stash is locked", "Unlock to see your logins and cards for this page.", button);
    button.focus();
    return;
  }
  rows = [];
  const sections = [];
  if (reply.logins.length) {
    sections.push(section(`Logins for ${reply.host}`, reply.logins.map((l) => row(l.name, l.username || "No username", "login", l.has_otp ? "2FA" : null))));
  } else {
    sections.push(el("p", { class: "empty" }, [`No logins saved for ${reply.host}. `, el("span", {}, "Add the site's address to a login in stash.")]));
  }
  const cards = reply.payments.filter((p) => p.kind === "card");
  const banks = reply.payments.filter((p) => p.kind === "bank");
  if (cards.length) sections.push(section("Cards", cards.map((c) => row(c.name, c.summary || "Card", "card"))));
  if (banks.length) sections.push(section("Bank accounts", banks.map((b) => row(b.name, b.summary || "Bank account", "bank"))));
  const search = el("input", { class: "search", type: "search", placeholder: "Search", "aria-label": "Search", oninput: filter });
  show(search, el("div", { class: "list", role: "listbox" }, sections));
  footer.hidden = false;
  select(0);
  search.focus();
}

function section(title, children) {
  return el("section", {}, [el("h2", {}, title), ...children]);
}

// Small line icons (24×24, stroked), built as DOM nodes rather than HTML.
const ICONS = {
  login: ["M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z", "M4 20c1.5-3.5 4.5-5 8-5s6.5 1.5 8 5"],
  card: ["M3 6.5h18v11H3z", "M3 10h18", "M6.5 14.5h4"],
  bank: ["M3 9.5 12 4l9 5.5", "M5 10v7M9.5 10v7M14.5 10v7M19 10v7", "M3 20h18"],
};

function icon(kind) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "16");
  svg.setAttribute("height", "16");
  for (const d of ICONS[kind]) {
    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
}

function row(name, detail, kind, badge) {
  const node = el("button", { class: "row", type: "button", role: "option", "data-kind": kind, onclick: () => pick(node, name, kind) }, [
    el("span", { class: "icon", "aria-hidden": "true" }, icon(kind)),
    el("span", { class: "text" }, [el("span", { class: "name" }, name), el("span", { class: "detail" }, detail)]),
    badge && el("span", { class: "badge" }, badge),
    kind !== "login" && el("span", { class: "touch", title: "Asks for Touch ID" }, "Touch ID"),
  ]);
  node.dataset.search = `${name} ${detail}`.toLowerCase();
  rows.push(node);
  return node;
}

function visibleRows() {
  return rows.filter((r) => !r.hidden);
}

function select(i) {
  const list = visibleRows();
  if (!list.length) return;
  selected = Math.max(0, Math.min(i, list.length - 1));
  list.forEach((r, k) => r.setAttribute("aria-selected", String(k === selected)));
  list[selected].scrollIntoView({ block: "nearest" });
}

function filter(event) {
  const q = event.target.value.trim().toLowerCase();
  for (const r of rows) r.hidden = q && !r.dataset.search.includes(q);
  for (const s of main.querySelectorAll("section")) s.hidden = !s.querySelector(".row:not([hidden])");
  select(0);
}

async function unlock() {
  message("Waiting for Touch ID…");
  render(await send({ type: "unlock" }));
}

async function pick(node, name, kind) {
  for (const r of rows) r.disabled = true;
  node.classList.add("busy");
  const detail = node.querySelector(".detail");
  detail.textContent = kind === "login" ? "Filling…" : "Waiting for Touch ID…";
  const reply = await send({ type: "fill", name, kind });
  if (!reply.ok) {
    if (reply.error === "stash is locked") return load();
    if (reply.error === "not-installed") return notInstalled();
    return message("Nothing was filled", errorText(reply.error));
  }
  if (!reply.filled.length) {
    return message("No fields to fill", kind === "login"
      ? "stash didn't find a visible sign-in form on this page."
      : "stash didn't find visible payment fields on this page.");
  }
  message("Filled ✓");
  setTimeout(() => window.close(), 500);
}

document.addEventListener("keydown", (event) => {
  if (event.key === "ArrowDown") select(selected + 1);
  else if (event.key === "ArrowUp") select(selected - 1);
  else if (event.key === "Enter") visibleRows()[selected]?.click();
  else return;
  event.preventDefault();
});

document.getElementById("lock").addEventListener("click", async () => {
  await send({ type: "lock" });
  load();
});

load().catch((e) => message("Something went wrong", String(e.message || e)));
