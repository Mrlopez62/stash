# Feature: browser autofill for logins and payments

**Status:** planned (roadmap v0.10). This document is the design to build it from. Nothing here exists yet.

## Goal

Fill sign-in forms and checkout forms in the browser from your stash vault, with the same safety rules as the rest of stash. Users get 1Password's "click the stash icon in the field, and it's filled" experience, while phishing pages and malicious scripts get nothing.

**In scope:**
- **Logins:** username, password, and the current 2FA code.
- **Payment cards:** cardholder, number, expiry, and security code (CVV).
- **Bank accounts:** account and routing numbers, on the rare forms that ask for them.
- **Browsers:** Chrome and Chromium browsers (Arc, Brave, Edge), Firefox, and Safari.

**Out of scope for the first version:**
- **Saving new logins** when you submit a form ("capture"). That comes in phase 5.
- **Passkeys.**
- **Mobile.**

## How it fits together

```
 web page ── content script ── extension ──(native messaging)── stash native-host ──(JSON-RPC)── stash app-server
             (finds fields,     (popup,                          (per-browser bridge,             (vault, Touch ID,
              fills on click)    matching)                         checks the extension ID)         validation)
```

**The extension never holds the vault key or caches secrets.** It asks for one value at a time, right before filling, the same way the Mac app does. `stash native-host` is a new hidden subcommand. The browser launches it through native messaging, and it relays the extension's requests to an `app-server`. That's either the running Mac app's backend or a fresh one, so the security logic stays in the Rust code that's already reviewed.

## The rules

1. **Origin matching is what stops phishing.** A login fills only on a page whose site matches the item's website.
   - **Matching:** by registrable domain (eTLD+1, using the Public Suffix List), with exact-host matching as an option per item.
   - **Off-site pages:** `github.com.evil.io` never matches `github.com`. Nothing is suggested there, and a click in the popup on that page fills nothing.
   - **Plain http:** pages that aren't https are never filled, except `localhost`.
2. **Filling always takes a click.** stash never fills when a page loads, and never fills hidden fields. You click the stash icon in a field, or choose an item in the popup. Fields must be visible, focusable, and in a frame the user is looking at. This also defeats invisible-form harvesting.
3. **Every payment fill needs Touch ID.** Card and bank fills always ask for a fingerprint, and the dialog names the site: *"fill Visa •••• 4242 on checkout.example.com"*. A login fill reuses the unlocked app's session, the same as copying from the app.
4. **Values only on demand.** The extension gets names, usernames, and card summaries (brand and last four) for its suggestion list. It gets the actual secret only for the one fill you clicked, then drops it.
5. **Card fields are found by the HTML standard.** Fields are matched by their `autocomplete` attribute (`cc-name`, `cc-number`, `cc-exp`, `cc-exp-month`, `cc-exp-year`, `cc-csc`, `postal-code`). Heuristics like labels and placeholders are only a fallback, and a field they find shows a confirmation before filling.
6. **Payment iframes are a known open question.** Checkout pages often put the card fields in a cross-origin iframe from a payment processor (for example, `js.stripe.com`). The proposed rule is to fill a card into a cross-origin frame only when:
   - the frame belongs to a short, built-in list of payment processors;
   - the top-level page is https;
   - the Touch ID dialog names the top-level site.
   This rule needs a security review before shipping (see open questions).
7. **The native host only talks to stash's own extensions.** It accepts connections only from stash's extension IDs, through each browser's `allowed_origins` / `allowed_extensions` manifest. It never accepts requests from web pages.

## Per-browser notes

| Browser | Extension | Native messaging | Distribution |
|---|---|---|---|
| Chrome / Arc / Brave / Edge | Manifest V3 | Host manifest in `~/Library/Application Support/<browser>/NativeMessagingHosts/` | Unpacked for development (free), or the Chrome Web Store ($5 one-time) |
| Firefox | WebExtension (MV3) | `~/Library/Application Support/Mozilla/NativeMessagingHosts/` | Signed by addons.mozilla.org (free) |
| Safari | Safari Web Extension inside `stash.app` | Built in, via the containing app | Needs Xcode and a **signed** app (Apple Developer account, $99/year). Ad-hoc builds only load with Safari's "Allow Unsigned Extensions", which resets every launch |

Because of the Safari row, Chrome and Firefox come first. Safari waits until there's a signed release.

## Build phases

1. **Chrome and Firefox: popup search and fill logins** on a click, with origin matching. This includes `stash native-host` and its install command (`stash browser install`).
2. **Inline icons:** a stash icon appears in detected username and password fields, and clicking it suggests matching logins. 2FA code fill.
3. **Payments:** card and bank fill, with Touch ID on every fill, detection through `autocomplete`, and the payment-iframe rule if its review approves it.
4. **Safari,** once releases are signed.
5. **Capture:** offer to save new logins and cards after you submit a form, and offer to update a saved password when it changes.

## Acceptance criteria

- **No fill without a match.** A login never fills, or is even suggested, on a page whose site doesn't match its website. Tests cover lookalike domains, subdomains, punycode, and http.
- **No fill without a click.** No fill happens without a user click. Tests confirm that loading a page, a script calling `focus()`, and hidden fields all fail to trigger one.
- **Payments ask every time.** Every payment fill shows a Touch ID prompt naming the site, and cancelling fills nothing.
- **Nothing kept in the extension.** Its storage holds no secret values, so a browser profile dump turns up names at most.
- **Only stash's extensions get in.** The native host rejects messages from unknown extension IDs.
- **The threat model gets an autofill section** before release.

## Open questions

- **Payment iframes:** is the iframe rule safe enough, or should payment fill be limited to same-origin fields at first?
- **Matching website changes:** if a site moves its login to a new domain, should stash offer to add it to the item's websites, or require editing the item?
- **CLI-only users:** should autofill work without the Mac app running, by having the native host start its own app-server and unlock with Touch ID?
