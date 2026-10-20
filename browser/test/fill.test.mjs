// Tests for the field-finding logic in extension/fill.js: `node --test browser/test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { classify, plan, capture, captureCard, formatExpiry, pickOption, frameAllowed } = require("../extension/fill.js");

const input = (props) => ({ tag: "input", type: "text", autocomplete: "", text: "", placeholder: "", maxLength: 0, form: "f", ...props });
const LOGIN = { username: "octocat", password: "hunter2!", otp: "123456" };
const CARD = { number: "4242424242424242", cvv: "123", cardholder: "Samus Aran", exp_month: "08", exp_year: "2027", postal_code: "12345" };

test("finds login fields by autocomplete first, then by name", () => {
  assert.equal(classify(input({ autocomplete: "username" }), "login"), "username");
  assert.equal(classify(input({ autocomplete: "section-x current-password" }), "login"), "password");
  assert.equal(classify(input({ type: "password" }), "login"), "password");
  assert.equal(classify(input({ type: "password", text: "Confirm password" }), "login"), "new-password");
  assert.equal(classify(input({ type: "email" }), "login"), "username");
  assert.equal(classify(input({ text: "login_email" }), "login"), "username");
  assert.equal(classify(input({ autocomplete: "one-time-code" }), "login"), "otp");
});

test("never mixes kinds: card fields aren't login fields, passwords aren't card fields", () => {
  assert.equal(classify(input({ autocomplete: "cc-number" }), "login"), null);
  assert.equal(classify(input({ type: "password" }), "card"), null);
  assert.equal(classify(input({ type: "hidden", autocomplete: "cc-number" }), "card"), null);
  assert.equal(classify(input({ type: "checkbox", text: "remember me" }), "login"), null);
});

test("fills username and password in the same form, not a search box elsewhere", () => {
  const fields = [
    input({ text: "search", form: "nav" }),
    input({ text: "login" }),
    input({ type: "password" }),
  ];
  assert.deepEqual(plan(fields, LOGIN, "login"), [[2, "hunter2!"], [1, "octocat"]]);
});

test("a sign-up form's new-password field is left alone", () => {
  const fields = [input({ autocomplete: "username" }), input({ type: "password", autocomplete: "new-password" })];
  assert.deepEqual(plan(fields, LOGIN, "login"), [[0, "octocat"]]);
});

test("a 2FA step gets the code, including split one-digit boxes", () => {
  assert.deepEqual(plan([input({ autocomplete: "one-time-code" })], LOGIN, "login"), [[0, "123456"]]);
  const boxes = Array.from({ length: 6 }, () => input({ maxLength: 1, type: "tel" }));
  assert.deepEqual(plan(boxes, LOGIN, "login").map(([, v]) => v).join(""), "123456");
});

test("fills a standard checkout form", () => {
  const fields = [
    input({ autocomplete: "cc-name" }),
    input({ autocomplete: "cc-number" }),
    input({ autocomplete: "cc-exp", placeholder: "MM / YY" }),
    input({ autocomplete: "cc-csc" }),
    input({ autocomplete: "billing postal-code" }),
  ];
  assert.deepEqual(plan(fields, CARD, "card"), [
    [0, "Samus Aran"], [1, "4242424242424242"], [2, "08 / 27"], [3, "123"], [4, "12345"],
  ]);
});

test("finds card fields by name when autocomplete is missing (like Stripe's)", () => {
  const fields = [input({ text: "cardnumber" }), input({ text: "exp-date", placeholder: "MM / YY" }), input({ text: "cvc" }), input({ text: "postal" })];
  assert.deepEqual(plan(fields, CARD, "card").map(([i]) => i), [0, 1, 2, 3]);
  // A shipping ZIP with no card fields around isn't filled.
  assert.deepEqual(plan([input({ text: "zip" })], CARD, "card"), []);
});

test("formats expiry dates the way each field wants", () => {
  assert.equal(formatExpiry("08", "2027", input({ placeholder: "MM/YY" })), "08/27");
  assert.equal(formatExpiry("08", "2027", input({ placeholder: "MM/YYYY" })), "08/2027");
  assert.equal(formatExpiry("08", "2027", input({ maxLength: 4 })), "0827");
  assert.equal(formatExpiry("08", "2027", input({ maxLength: 7 })), "08/2027");
});

test("picks month and year options in selects", () => {
  const months = [{ value: "", text: "Month" }, { value: "1", text: "January" }, { value: "8", text: "August" }];
  assert.equal(pickOption(months, "08", "cc-exp-month").text, "August");
  const named = [{ value: "jan", text: "Jan" }, { value: "aug", text: "Aug" }];
  assert.equal(pickOption(named, "08", "cc-exp-month").value, "aug");
  const years = [{ value: "26", text: "2026" }, { value: "27", text: "2027" }];
  assert.equal(pickOption(years, "2027", "cc-exp-year").value, "27");
  assert.equal(pickOption(years, "2031", "cc-exp-year"), undefined);
});

test("fills bank account fields", () => {
  const fields = [input({ text: "Routing number" }), input({ text: "Account number" }), input({ text: "Account holder name" })];
  assert.deepEqual(plan(fields, { routing: "021000021", account: "000123456789", holder: "Samus Aran" }, "bank"), [
    [0, "021000021"], [1, "000123456789"], [2, "Samus Aran"],
  ]);
});

test("frames: logins only on the approved origin, cards also in a processor frame directly in it", () => {
  const page = "https://shop.example";
  const stripe = "https://js.stripe.com";
  assert.equal(frameAllowed("login", page, page, [], false), true);
  assert.equal(frameAllowed("login", page, "https://ads.example", [page], true), false);
  assert.equal(frameAllowed("login", page, stripe, [page], true), false, "no logins in card frames");
  assert.equal(frameAllowed("card", page, stripe, [page], true), true);
  assert.equal(frameAllowed("card", page, stripe, ["https://evil.example"], true), false);
  assert.equal(frameAllowed("card", page, "https://evil.example", [page], true), false);
});

test("a card frame nested inside another frame (like an ad) never gets the card", () => {
  const page = "https://shop.example";
  const stripe = "https://js.stripe.com";
  // Chrome: the ad frame is the nearest ancestor, even though the top is right.
  assert.equal(frameAllowed("card", page, stripe, ["https://ads.example", page], false), false);
  assert.equal(frameAllowed("card", page, stripe, ["https://ads.example", page], true), false);
  // Firefox reports no ancestors: only the direct-child test decides.
  assert.equal(frameAllowed("card", page, stripe, undefined, false), false);
  assert.equal(frameAllowed("card", page, stripe, undefined, true), true);
});

test("the billing ZIP never goes into a shipping ZIP", () => {
  assert.equal(classify(input({ text: "Shipping ZIP" }), "card"), null);
  const fields = [input({ text: "zip code" }), input({ autocomplete: "cc-number" }), input({ autocomplete: "billing postal-code" })];
  assert.deepEqual(plan(fields, CARD, "card"), [[1, "4242424242424242"], [2, "12345"]]);
});

test("offers to save the password used to sign in, with its username", () => {
  const fields = [input({ text: "search", value: "cats", form: "nav" }), input({ type: "email", value: " me@x.com " }), input({ type: "password", value: "s3cret" })];
  assert.deepEqual(capture(fields), { username: "me@x.com", password: "s3cret" });
});

test("a sign-up saves the new password, and only if both copies agree", () => {
  const signup = (confirm) => [
    input({ autocomplete: "username", value: "octocat" }),
    input({ type: "password", autocomplete: "new-password", value: "Correct-Horse-1" }),
    input({ type: "password", autocomplete: "new-password", value: confirm }),
  ];
  assert.deepEqual(capture(signup("Correct-Horse-1")), { username: "octocat", password: "Correct-Horse-1" });
  assert.equal(capture(signup("Correct-Horse-2")), null, "a mistyped confirmation saves nothing");
});

test("a password change saves the new password, not the old one", () => {
  const fields = [
    input({ type: "password", autocomplete: "current-password", value: "old" }),
    input({ type: "password", autocomplete: "new-password", value: "new!" }),
  ];
  assert.deepEqual(capture(fields), { username: "", password: "new!" });
});

test("nothing to save without a password", () => {
  assert.equal(capture([input({ type: "email", value: "me@x.com" })]), null);
  assert.equal(capture([input({ type: "password", value: "" })]), null);
});

test("finds the card in a submitted checkout, whatever the expiry fields look like", () => {
  const card = (exp) => [
    input({ autocomplete: "cc-name", value: "Samus Aran" }),
    input({ autocomplete: "cc-number", value: "4242 4242 4242 4242" }),
    ...exp,
    input({ autocomplete: "cc-csc", value: "123" }),
    input({ autocomplete: "billing postal-code", value: "12345" }),
  ];
  const want = { number: "4242424242424242", cardholder: "Samus Aran", exp_month: "08", exp_year: "2027", cvv: "123", postal_code: "12345" };
  assert.deepEqual(captureCard(card([input({ autocomplete: "cc-exp", value: "08 / 27" })])), want);
  assert.deepEqual(captureCard(card([input({ autocomplete: "cc-exp", value: "0827" })])), want);
  assert.deepEqual(
    captureCard(card([{ ...input({ autocomplete: "cc-exp-month", value: "8" }), tag: "select" }, { ...input({ autocomplete: "cc-exp-year", value: "2027" }), tag: "select" }])),
    want,
  );
});

test("a number that fails the card checksum isn't treated as a card", () => {
  assert.equal(captureCard([input({ autocomplete: "cc-number", value: "4242 4242 4242 4241" })]), null);
  assert.equal(captureCard([input({ text: "gift card code", value: "1234567890" })]), null);
  assert.equal(captureCard([input({ type: "password", value: "x" })]), null);
});
