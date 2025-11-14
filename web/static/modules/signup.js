/**
 * Signup module for Nostr-based account creation
 * Follows the same pattern as login.js - server generates challenge, frontend signs it
 */

export async function signNostrEvent(event) {
  if (!window.nostr) {
    throw new Error("window.nostr is not set. You need a NIP-07 extension");
  }
  return await window.nostr.signEvent(event);
}

/**
 * Show notification using the Notifications template
 * @param {string} message - The notification message
 * @param {string} type - The notification type (success, error, warning, info)
 */
function showNotification(message, type) {
  const notificationsDiv = document.getElementById('notifications');
  if (!notificationsDiv) return;

  const notificationHTML = `
    <div id="snackbar" remove-me="3s" class="${type}">
      <span>${message}</span>
    </div>
  `;

  notificationsDiv.innerHTML += notificationHTML;

  // Trigger htmx processing for the new notification
  if (window.htmx) {
    window.htmx.process(notificationsDiv);
  }
}

/**
 * Initialize the signup form
 */
export function initSignup() {
  const signupForm = document.getElementById('signupForm');
  if (!signupForm) return;

  signupForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const submitButton = signupForm.querySelector('button[type="submit"]');

    // Check if Nostr extension is available
    if (!window.nostr) {
      showNotification('Nostr extension not found. Please install a Nostr browser extension (nos2x, Alby, etc.)', 'error');
      return;
    }

    try {
      // Disable submit button during signing
      submitButton.disabled = true;
      submitButton.textContent = 'Signing...';

      // Get the challenge from the form attributes (set by server)
      const challenge = signupForm.attributes.challenge.value;
      if (!challenge) {
        showNotification('Challenge not found. Please refresh and try again.', 'error');
        submitButton.disabled = false;
        submitButton.textContent = 'Sign Up with Nostr';
        return;
      }

      // Create event for signing (matching login.js pattern)
      // Kind 22242 is used for authentication challenges
      const eventToSign = {
        kind: 22242,
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: challenge,
      };

      // Request signature from Nostr extension
      const signedEvent = await signNostrEvent(eventToSign);

      // Update button text
      submitButton.textContent = 'Creating Account...';

      // Send the signed event to the backend (matching login.js pattern)
      const signupUrl = '/signup';
      const res = await fetch(new Request(signupUrl, {
        method: 'POST',
        body: JSON.stringify(signedEvent),
      }));

      console.log({ res })
      const text = await res.text();

      if (res.ok) {
        // Success - swap the entire body with success page
        const targetHeader = res.headers.get("HX-RETARGET");
        if (targetHeader) {
          window.htmx.swap(`${targetHeader}`, text, { swapStyle: "innerHTML" });
          return
        }

        window.htmx.swap('#body-children', text, { swapStyle: 'innerHTML' });
        showNotification('Account created successfully!', 'success');
      } else {
        const targetHeader = res.headers.get("HX-RETARGET");
        if (window.htmx && targetHeader) {
          window.htmx.swap(`${targetHeader}`, text, { swapStyle: "innerHTML" });
        }
      }
    } catch (error) {
      console.error('Signup error:', error);

      if (error.message.includes('user denied')) {
        showNotification('Signing cancelled. Please approve the signature request in your Nostr extension', 'error');
      } else if (error.message.includes('NIP-07')) {
        showNotification('Nostr extension not found. Please install a Nostr browser extension', 'error');
      } else {
        showNotification(`Error during signing: ${error.message}`, 'error');
      }

      submitButton.disabled = false;
      submitButton.textContent = 'Sign Up with Nostr';
    }
  });
}
