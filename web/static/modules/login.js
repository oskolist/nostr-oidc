// modules/login.js

import htmx from "htmx.org";

export async function signNostrEvent(event) {
  if (!window.nostr) {
    throw Error("window nostr is not set. You need a NIP-07 extension");
  }
  return await window.nostr.signEvent(event);
}

export function initLogin() {
  const loginContainer = document.getElementById("loginContainer");
  if (!loginContainer) return;

  loginContainer.addEventListener("submit", async (e) => {
    e.preventDefault();

    console.log("nonce: ", loginContainer?.nonce)
    const eventToSign = {
      created_at: Math.floor(Date.now() / 1000),
      kind: 27235,
      tags: [],
      content: loginContainer.nonce,
    };

    try {
      const signedEvent = await signNostrEvent(eventToSign);
      let loginUrl = "/login"

      if (loginContainer.dataset.loginType) {
        loginUrl = "/device/login"

      }
      const res = await fetch(new Request(loginUrl, {
        method: "POST",
        body: JSON.stringify(signedEvent),
      }));

      if (res.ok) {
        const targetHeader = res.headers.get("HX-RETARGET");
        if (targetHeader) {
          window.htmx.swap(`${targetHeader}`, text, { swapStyle: "innerHTML" });
          return
        }
        const text = await res.text();
        window.htmx.swap(`#body-children`, text, { swapStyle: "innerHTML" });
      } else {
        const targetHeader = res.headers.get("HX-RETARGET");
        if (window.htmx && targetHeader) {
          const text = await res.text();
          window.htmx.swap(`#${targetHeader}`, text, { swapStyle: "innerHTML" });
        }
      }
    } catch (err) {
      console.log("Login error", err);
    }
  });
}
