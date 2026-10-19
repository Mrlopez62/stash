// stash in sign-in fields: an icon in username and password fields that
// opens the stash menu, and an offer to save a login after you sign in.
//
// Runs only if you turn it on (Settings → "Show stash in sign-in fields"),
// which grants the extension access to sites. Even then:
//
// - The menu and the save prompt are extension pages in frames: the page
//   can't read or change them, so it can't fake a choice or see your logins.
// - The icon opens the menu only for a real click (`isTrusted`), never for
//   a script's.
// - Filling still goes through the background and the vault's checks: a
//   login fills only on its own site, payments need Touch ID.
// - What a form held at submit goes to the background only to offer saving;
//   nothing is saved until you click Save in stash's own prompt.

(function () {
  "use strict";
  if (globalThis.__stashInline) return;
  globalThis.__stashInline = true;
  const fields = globalThis.__stashFields;
  if (!fields) return;

  // Everything stash draws lives in one closed shadow root, so the page's
  // styles and scripts can't reach in.
  const host = document.createElement("stash-autofill");
  const shadow = host.attachShadow({ mode: "closed" });
  shadow.innerHTML = `
    <style>
      :host { all: initial; }
      .icon {
        position: fixed; z-index: 2147483647; width: 22px; height: 22px; padding: 0; border: 0;
        border-radius: 5px; background: #0E1116 url("${chrome.runtime.getURL("icons/icon-32.png")}") center / 22px no-repeat;
        box-shadow: 0 1px 3px rgba(0,0,0,.25); cursor: pointer; opacity: .92;
      }
      .icon:hover { opacity: 1; }
      .icon[hidden], iframe[hidden] { display: none; }
      iframe {
        position: fixed; z-index: 2147483647; border: 0; border-radius: 12px;
        box-shadow: 0 8px 30px rgba(0,0,0,.25); background: transparent; color-scheme: normal;
      }
    </style>
    <button class="icon" type="button" title="Fill with stash" aria-label="Fill with stash" hidden></button>
    <iframe class="menu" title="stash" hidden></iframe>
    <iframe class="save" title="Save to stash" hidden></iframe>`;
  const icon = shadow.querySelector(".icon");
  const menu = shadow.querySelector(".menu");
  const save = shadow.querySelector(".save");
  let field = null;
  let hideTimer = null;

  function attach() {
    if (!host.isConnected) document.documentElement.append(host);
  }

  function isLoginField(el) {
    if (!(el instanceof HTMLInputElement) || !fields.visible(el)) return false;
    const kind = fields.classify(fields.describe(el), "login");
    return kind === "username" || kind === "password" || kind === "new-password";
  }

  function place() {
    if (!field || !field.isConnected) return hideIcon();
    const r = field.getBoundingClientRect();
    icon.style.left = `${Math.round(r.right - 28)}px`;
    icon.style.top = `${Math.round(r.top + (r.height - 22) / 2)}px`;
    if (!menu.hidden) {
      menu.style.left = `${Math.round(Math.min(r.left, window.innerWidth - 352))}px`;
      menu.style.top = `${Math.round(r.bottom + 6)}px`;
    }
  }

  function showIcon(el) {
    clearTimeout(hideTimer);
    field = el;
    attach();
    icon.hidden = false;
    place();
  }

  function hideIcon() {
    icon.hidden = true;
    if (menu.hidden) field = null;
  }

  function openMenu() {
    if (!field) return;
    attach();
    menu.src = chrome.runtime.getURL("menu.html");
    menu.style.width = "340px";
    menu.style.height = "360px";
    menu.hidden = false;
    place();
  }

  function closeMenu() {
    menu.hidden = true;
    menu.removeAttribute("src");
  }

  document.addEventListener("focusin", (e) => {
    if (isLoginField(e.target)) showIcon(e.target);
  }, true);
  document.addEventListener("focusout", (e) => {
    if (e.target === field) hideTimer = setTimeout(hideIcon, 250);
  }, true);
  window.addEventListener("scroll", place, true);
  window.addEventListener("resize", place);

  // Only a person's click opens the menu; a script's `click()` doesn't.
  icon.addEventListener("mousedown", (e) => e.preventDefault());
  icon.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    e.preventDefault();
    if (menu.hidden) openMenu();
    else closeMenu();
  });
  document.addEventListener("mousedown", (e) => {
    if (!menu.hidden && !e.composedPath().includes(host)) closeMenu();
  }, true);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !menu.hidden) closeMenu();
  }, true);

  // ---- Offer to save ----

  /// The fields of a form (or the page), as they were at submit.
  function snapshot(form, selector) {
    const scope = form || document;
    return Array.from(scope.querySelectorAll(selector))
      .filter((el) => fields.visible(el) || el.type === "password")
      .map((el) => ({ ...fields.describe(el), value: el.value }));
  }

  const sent = new Set();
  function sendOnce(key, message) {
    if (sent.has(key)) return;
    sent.add(key);
    chrome.runtime.sendMessage(message).catch(() => {});
  }

  /// Offer to save what this form held. A login is offered on any sign-in
  /// action (many sign-in forms submit with a script); a card only when the
  /// form is really submitted, so "Apply coupon" or "Back" on a checkout
  /// never offers to save the card.
  function captureFrom(form, submitted) {
    // Logins from text inputs only (a dropdown is never a username).
    const login = fields.capture(snapshot(form, "input"));
    if (login) {
      sendOnce(`login\u0000${login.username}\u0000${login.password}`, {
        type: "captured",
        username: login.username,
        password: login.password,
      });
    }
    if (submitted) {
      // Cards may use dropdowns for the expiry.
      const card = fields.captureCard(snapshot(form, "input, select"));
      if (card) sendOnce(`card\u0000${card.number}`, { type: "captured-card", card });
    }
  }

  /// A click on the button that submits its form (not "Apply coupon").
  function isSubmitButton(el) {
    if (!el.form) return false;
    if (el instanceof HTMLInputElement) return el.type === "submit" || el.type === "image";
    return el instanceof HTMLButtonElement && (el.getAttribute("type") || "submit").toLowerCase() === "submit";
  }

  document.addEventListener("submit", (e) => captureFrom(e.target, true), true);
  document.addEventListener("click", (e) => {
    if (!e.isTrusted || !(e.target instanceof Element)) return;
    const button = e.target.closest("button, input[type=submit], input[type=image], [role=button]");
    if (!button) return;
    if (isSubmitButton(button)) return captureFrom(button.form, true);
    // Many sign-in forms submit with a script instead of a real submit;
    // those offer a login only.
    const form = button.closest("form") || (field && field.form) || null;
    if (form || document.querySelector("input[type=password]")) captureFrom(form, false);
  }, true);
  document.addEventListener("keydown", (e) => {
    // Enter submits a form the usual way (and fires `submit`, above);
    // here it only stands in for script-driven sign-ins.
    if (e.key === "Enter" && e.isTrusted && e.target instanceof HTMLInputElement) captureFrom(e.target.form, false);
  }, true);

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "stash-close-menu") closeMenu();
    if (message.type === "stash-show-save" && window === window.top) {
      attach();
      save.src = chrome.runtime.getURL(`save.html#${encodeURIComponent(message.token)}`);
      Object.assign(save.style, { width: "340px", height: "150px", top: "16px", right: "16px" });
      save.hidden = false;
    }
    if (message.type === "stash-hide-save") {
      save.hidden = true;
      save.removeAttribute("src");
    }
  });
})();
