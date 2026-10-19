// stash settings: turning sign-in field icons and save offers on or off is
// granting or removing the extension's access to sites.

"use strict";

const ORIGINS = { origins: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"] };
const box = document.getElementById("inline");
const status = document.getElementById("status");

async function refresh() {
  box.checked = await chrome.permissions.contains(ORIGINS);
  status.textContent = box.checked ? "On." : "Off.";
}

box.addEventListener("change", async () => {
  try {
    if (box.checked) {
      const granted = await chrome.permissions.request(ORIGINS);
      if (!granted) status.textContent = "Not turned on: the browser's permission wasn't granted.";
    } else {
      await chrome.permissions.remove(ORIGINS);
    }
  } finally {
    await refresh();
  }
});

refresh();
