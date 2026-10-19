// stash: the "save this login?" prompt, shown in a frame of stash's own
// after you sign in. Only a click here saves anything.

"use strict";

const token = decodeURIComponent(location.hash.slice(1));
const title = document.getElementById("title");
const detail = document.getElementById("detail");
const yes = document.getElementById("yes");
const no = document.getElementById("no");
const send = (message) => chrome.runtime.sendMessage({ ...message, token });

let info = null;

async function load() {
  info = await send({ type: "save-info" });
  if (!info.ok) return send({ type: "save-dismiss" });
  const who = info.username ? info.username : "this login";
  if (info.kind === "card") {
    title.textContent = "Save this card to stash?";
    detail.textContent = `${info.summary}, from ${info.host}. Saving asks for Touch ID.`;
  } else if (info.state === "changed") {
    title.textContent = `Update your ${info.host} password?`;
    detail.textContent = `stash will save the new password for ${who} and keep the old one in the item.`;
    yes.textContent = "Update";
  } else {
    title.textContent = `Save your ${info.host} login?`;
    detail.textContent = info.username ? `For ${info.username}.` : "Without a username.";
  }
  yes.focus();
}

yes.addEventListener("click", async (event) => {
  if (!event.isTrusted) return;
  yes.disabled = no.disabled = true;
  yes.textContent = info?.kind === "card" ? "Waiting for Touch ID…" : "Saving…";
  const reply = await send({ type: "save-confirm" });
  if (reply.ok) {
    title.textContent = reply.action === "unchanged" ? "Already in stash ✓" : "Saved to stash ✓";
    if (info?.kind === "card") yes.textContent = "Save";
    detail.textContent = `As ${reply.name}.`;
  } else {
    title.textContent = "Not saved";
    detail.textContent = reply.error === "cancelled" ? "Touch ID was cancelled." : reply.error;
  }
  document.querySelector(".actions").hidden = true;
  setTimeout(() => send({ type: "save-dismiss" }), 1800);
});

no.addEventListener("click", () => send({ type: "save-dismiss" }));
document.addEventListener("keydown", (e) => e.key === "Escape" && send({ type: "save-dismiss" }));

load().catch(() => send({ type: "save-dismiss" }));
