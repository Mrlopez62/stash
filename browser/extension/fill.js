// stash autofill: finds the fields to fill on a page and fills them.
//
// Injected by the background script into the active tab only after the user
// picks an item in the stash popup, and only with values the native host
// released for this page. It runs once per frame and fills nothing unless:
//
// - the frame's origin is the page the host approved (logins: exactly that
//   origin; cards: that origin, or a known payment processor's frame placed
//   *directly* in the approved page, like Stripe's card fields),
// - the frame is visible, and each field is visible, enabled, and editable.
//
// Fields are found by the HTML `autocomplete` standard first
// (`current-password`, `cc-number`, `cc-exp`, ...), then by their names and
// labels. The logic is plain functions so it can be tested outside a browser
// (browser/test/fill.test.mjs).

(function () {
  "use strict";

  // Frames from these origins may receive card details, but only inside a
  // page the host approved. They host the card fields of most checkouts.
  const PAYMENT_PROCESSORS = ["https://js.stripe.com", "https://assets.braintreegateway.com"];

  const FILLABLE_TYPES = new Set(["", "text", "email", "tel", "password", "number", "search", "url"]);

  // `autocomplete` tokens, after dropping section-*, shipping, and billing.
  const AUTOCOMPLETE = {
    username: "username",
    email: "username",
    "current-password": "password",
    password: "password",
    "new-password": "new-password",
    "one-time-code": "otp",
    "cc-name": "cc-name",
    "cc-number": "cc-number",
    "cc-exp": "cc-exp",
    "cc-exp-month": "cc-exp-month",
    "cc-exp-year": "cc-exp-year",
    "cc-csc": "cc-csc",
    "postal-code": "postal-code",
  };

  // Names, ids, placeholders, and labels, by what the form is for.
  const HINTS = {
    login: [
      ["otp", /one.?time|\botp\b|totp|2fa|two.?factor|mfa|verification.?code|auth(entication)?.?code|security.?code|\bcode\b/],
      ["username", /user|e-?mail|login|account.?name|identifier/],
    ],
    card: [
      ["cc-number", /card.?num|cc.?num|cardnumber|credit.?card|card.?no\b|\bpan\b/],
      ["cc-csc", /\bcvc|\bcvv|\bcsc|\bcvn|security.?code|card.?code|card.?verif/],
      ["cc-exp-month", /exp.*mon|card.?mon|\bmm\b(?!.*yy)/],
      ["cc-exp-year", /exp.*y(ea)?r|card.?y(ea)?r|^\s*yy(yy)?\s*$/],
      ["cc-exp", /exp(iry|iration)?|mm.?\/.?yy|valid.?(thru|through)/],
      ["cc-name", /name.?on.?card|card.?holder|cardholder|cc.?name|name.?on.?the.?card/],
      ["postal-code", /zip|postal|post.?code/],
    ],
    bank: [
      ["bank-routing", /routing|\baba\b/],
      ["bank-account", /account.?(number|num|no)\b|acct.?(number|num|no)|bank.?account(?!.*(name|holder|type))/],
      ["bank-holder", /account.?holder|name.?on.?account|account.?name/],
    ],
  };

  function tokens(autocomplete) {
    return (autocomplete || "")
      .toLowerCase()
      .split(/\s+/)
      .filter((t) => t && !t.startsWith("section-") && t !== "shipping" && t !== "billing");
  }

  /// What a field is, in `mode` ("login", "card", or "bank"), or null.
  /// `d` describes the field: tag, type, autocomplete, and the text around
  /// it (name, id, placeholder, label, aria-label).
  function classify(d, mode) {
    const type = (d.type || "").toLowerCase();
    if (d.tag === "input" && !FILLABLE_TYPES.has(type)) return null;
    const auto = tokens(d.autocomplete).map((t) => AUTOCOMPLETE[t]).find(Boolean);
    const forMode = (kind) =>
      mode === "login"
        ? ["username", "password", "new-password", "otp"].includes(kind)
        : mode === "card"
          ? kind.startsWith("cc-") || kind === "postal-code"
          : kind.startsWith("bank-");
    if (auto && forMode(auto)) return auto;
    if (auto) return null; // Labeled for something else (e.g. a card field on a login fill).
    if (type === "password") {
      if (mode !== "login") return null;
      return /new|confirm|repeat|again|retype/i.test(d.text || "") ? "new-password" : "password";
    }
    const text = (d.text || "").toLowerCase();
    for (const [kind, pattern] of HINTS[mode] || []) {
      if (!pattern.test(text)) continue;
      // A shipping or delivery ZIP isn't the card's billing ZIP.
      if (kind === "postal-code" && /ship|deliver/.test(text)) return null;
      return kind;
    }
    if (mode === "login" && type === "email") return "username";
    return null;
  }

  /// Format an expiry for a field, from its length and placeholder:
  /// "08/27", "08/2027", or "0827".
  function formatExpiry(month, year, d) {
    const placeholder = (d.placeholder || "").toLowerCase();
    const yy = year.slice(-2);
    if (/yyyy/.test(placeholder) || (d.maxLength >= 7 && !/yy\b/.test(placeholder))) return `${month}/${year}`;
    if (d.maxLength === 4) return `${month}${yy}`;
    if (/ \/ /.test(placeholder)) return `${month} / ${yy}`;
    return `${month}/${yy}`;
  }

  /// The option of a <select> that means `value` (a month or a year).
  function pickOption(options, value, kind) {
    const n = parseInt(value, 10);
    const months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    return options.find((o) => {
      const v = (o.value || "").trim().toLowerCase();
      const t = (o.text || "").trim().toLowerCase();
      if (kind === "cc-exp-month") {
        return parseInt(v, 10) === n || parseInt(t, 10) === n || t.startsWith(months[n - 1]) || v.startsWith(months[n - 1]);
      }
      return v === value || t === value || v === value.slice(-2) || t === value.slice(-2);
    });
  }

  /// Decide which value goes in which field. `fields` are descriptors in
  /// page order (with `form`, an identity for the enclosing form); returns
  /// [index, value] pairs.
  function plan(fields, values, mode) {
    const kinds = fields.map((f) => classify(f, mode));
    const out = [];
    if (mode === "login") {
      const pw = kinds.indexOf("password");
      if (pw >= 0 && values.password) {
        out.push([pw, values.password]);
        if (values.username) {
          // The closest username field before the password, in its form.
          let user = -1;
          for (let i = pw - 1; i >= 0; i--) {
            if (fields[i].form !== fields[pw].form) continue;
            if (kinds[i] === "username") { user = i; break; }
            if (user < 0 && ["text", "email", "tel", ""].includes((fields[i].type || "").toLowerCase()) && fields[i].tag === "input" && kinds[i] !== "otp") user = i;
          }
          if (user >= 0) out.push([user, values.username]);
        }
        return out;
      }
      // No password field: a username step, or a 2FA step.
      const otpBoxes = fields.map((f, i) => i).filter((i) => fields[i].maxLength === 1 && kinds[i] !== "password");
      if (values.otp && otpBoxes.length >= 4 && otpBoxes.length <= 8) {
        otpBoxes.forEach((i, k) => k < values.otp.length && out.push([i, values.otp[k]]));
        return out;
      }
      const otp = kinds.indexOf("otp");
      if (values.otp && otp >= 0) return [[otp, values.otp]];
      const user = kinds.indexOf("username");
      if (values.username && user >= 0) return [[user, values.username]];
      return out;
    }
    if (mode === "card") {
      const hasCard = kinds.some((k) => k && k.startsWith("cc-"));
      // If the page marks its billing ZIP with autocomplete, fill only that.
      const markedZip = fields.some((f, i) => kinds[i] === "postal-code" && tokens(f.autocomplete).includes("postal-code"));
      kinds.forEach((kind, i) => {
        if (kind === "postal-code" && markedZip && !tokens(fields[i].autocomplete).includes("postal-code")) kinds[i] = null;
      });
      kinds.forEach((kind, i) => {
        const f = fields[i];
        let v = null;
        if (kind === "cc-number") v = values.number;
        else if (kind === "cc-csc") v = values.cvv;
        else if (kind === "cc-name") v = values.cardholder;
        else if (kind === "cc-exp" && values.exp_month) v = formatExpiry(values.exp_month, values.exp_year, f);
        else if (kind === "cc-exp-month") v = values.exp_month;
        else if (kind === "cc-exp-year") v = f.tag !== "select" && f.maxLength === 2 ? values.exp_year?.slice(-2) : values.exp_year;
        else if (kind === "postal-code" && hasCard) v = values.postal_code;
        if (v) out.push([i, v]);
      });
      return out;
    }
    if (mode === "bank") {
      kinds.forEach((kind, i) => {
        const v = { "bank-routing": values.routing, "bank-account": values.account || values.iban, "bank-holder": values.holder }[kind];
        if (v) out.push([i, v]);
      });
    }
    return out;
  }

  /// What to offer to save from a submitted form, or null. `fields` are
  /// descriptors with the `value` each held at submit: a sign-up or
  /// password change saves the new password, a sign-in the password used.
  function capture(fields) {
    const kinds = fields.map((f) => classify(f, "login"));
    const withValue = (i) => (fields[i].value || "").length > 0;
    const newPw = kinds.findIndex((k, i) => k === "new-password" && withValue(i));
    const curPw = kinds.findIndex((k, i) => k === "password" && withValue(i));
    const pw = newPw >= 0 ? newPw : curPw;
    if (pw < 0) return null;
    // A sign-up's "confirm password" must agree, or it was a typo.
    const confirm = kinds.findIndex((k, i) => k === "new-password" && i !== newPw && withValue(i));
    if (newPw >= 0 && confirm >= 0 && fields[confirm].value !== fields[newPw].value) return null;
    let user = kinds.findIndex((k, i) => k === "username" && withValue(i));
    if (user < 0) {
      for (let i = Math.min(curPw >= 0 ? curPw : pw, pw) - 1; i >= 0; i--) {
        const t = (fields[i].type || "").toLowerCase();
        if (fields[i].tag === "input" && ["text", "email", "tel", ""].includes(t) && withValue(i) && fields[i].form === fields[pw].form) {
          user = i;
          break;
        }
      }
    }
    return { username: user >= 0 ? fields[user].value.trim() : "", password: fields[pw].value };
  }

  // ---- DOM ----

  function labelText(el) {
    const doc = el.ownerDocument;
    const parts = [el.name, el.id, el.placeholder, el.getAttribute("aria-label"), el.getAttribute("data-testid")];
    if (el.id) {
      const label = doc.querySelector(`label[for="${CSS.escape(el.id)}"]`);
      if (label) parts.push(label.textContent);
    }
    const wrapping = el.closest("label");
    if (wrapping) parts.push(wrapping.textContent);
    const labelledBy = el.getAttribute("aria-labelledby");
    if (labelledBy) for (const id of labelledBy.split(/\s+/)) parts.push(doc.getElementById(id)?.textContent);
    return parts.filter(Boolean).join(" ").slice(0, 300);
  }

  function visible(el) {
    if (el.disabled || el.readOnly) return false;
    const rect = el.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2) return false;
    const view = el.ownerDocument.defaultView;
    for (let node = el; node && node.nodeType === 1; node = node.parentElement) {
      const style = view.getComputedStyle(node);
      if (style.display === "none" || style.visibility === "hidden" || parseFloat(style.opacity) < 0.1) return false;
    }
    return true;
  }

  function describe(el) {
    return {
      tag: el.tagName.toLowerCase(),
      type: el.tagName === "INPUT" ? el.getAttribute("type") || "text" : "",
      autocomplete: el.getAttribute("autocomplete") || "",
      text: labelText(el),
      placeholder: el.placeholder || "",
      maxLength: el.maxLength > 0 && el.maxLength < 1000 ? el.maxLength : 0,
      form: el.form || null,
    };
  }

  function setValue(el, value, kind) {
    if (el.tagName === "SELECT") {
      const option = pickOption(Array.from(el.options), value, kind);
      if (!option) return false;
      el.value = option.value;
    } else {
      // The native setter, so frameworks that track values (React) see it.
      const proto = Object.getPrototypeOf(el);
      const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
      if (setter) setter.call(el, value);
      else el.value = value;
    }
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  }

  /// May this frame be filled? `expectedOrigin` is the page the host
  /// approved; `directChild` says whether this frame's parent is the top
  /// page; `ancestorOrigins` lists the frame's ancestors, nearest first,
  /// where the browser reports them (Chrome, Safari; not Firefox).
  function frameAllowed(mode, expectedOrigin, here, ancestorOrigins, directChild) {
    if (here === expectedOrigin) return true;
    if (mode !== "card" || !PAYMENT_PROCESSORS.includes(here)) return false;
    // A processor's frame only directly inside the approved page: not
    // nested in some other frame (an ad could embed its own card form).
    if (!directChild) return false;
    if (ancestorOrigins && ancestorOrigins.length) return ancestorOrigins[0] === expectedOrigin;
    return true;
  }

  function isDirectChild() {
    try {
      return window.parent === window.top && window !== window.top;
    } catch {
      return false;
    }
  }

  /// Phase one: may this frame be filled? Nothing secret is sent yet.
  function check({ expectedOrigin, mode }) {
    return (
      frameAllowed(mode, expectedOrigin, location.origin, location.ancestorOrigins, isDirectChild()) &&
      document.visibilityState === "visible"
    );
  }

  /// Phase two: fill. Runs only in frames that passed the check, and checks
  /// again.
  function fill({ expectedOrigin, mode, values }) {
    if (!check({ expectedOrigin, mode })) return { filled: [] };
    const elements = Array.from(document.querySelectorAll("input, select")).filter(visible);
    const fields = elements.map(describe);
    const filled = [];
    for (const [i, value] of plan(fields, values, mode)) {
      const kind = classify(fields[i], mode);
      if (setValue(elements[i], value, kind)) filled.push(kind);
    }
    return { filled };
  }

  const api = { classify, plan, capture, formatExpiry, pickOption, frameAllowed, PAYMENT_PROCESSORS };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    globalThis.__stashCheck = check;
    globalThis.__stashFill = fill;
    // For inline.js (stash in sign-in fields), in the same isolated world.
    globalThis.__stashFields = { classify, capture, describe, visible };
  }
})();
