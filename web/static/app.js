// App.js entry point: import and boot all modules

// Login functionality
import { initLogin } from './modules/login.js';

// Signup functionality
import { initSignup } from './modules/signup.js';

// Certificate copy functionality
import { initCertCopy } from './modules/certs.js';

// Form behavior (editable card names)
import { initCardInputs } from './modules/forms.js';

// Client form functionality
import { initClientForm } from './modules/client-form.js';

// Initialize everything when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  initLogin();
  initSignup();
  initCertCopy();
  initCardInputs();
  initClientForm();
});

// Re-init card inputs after HTMX swaps (new fragments)
if (typeof document !== 'undefined') {
  document.body.addEventListener('htmx:afterSwap', (e) => {
    const root = e && e.target ? e.target : document;
    initCardInputs(root);
    initSignup();
    initClientForm(root);
  });
}

console.log('App initialized');
