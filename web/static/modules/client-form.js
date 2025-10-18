// modules/client-form.js
// Handles dynamic input list management for the client form

/**
 * Add a new item to a multi-input list
 * @param {string} inputName - The name of the input field
 */
function addInput(inputName) {
  const inputField = document.getElementById(inputName + '_input');
  const container = document.getElementById(inputName + '_container');

  if (!inputField || !container) return;

  const value = inputField.value.trim();
  if (!value) return;

  // Create new list item
  const newItem = document.createElement('div');
  newItem.className = 'flex items-center justify-between px-3 py-2 bg-gray-50 border border-gray-200 rounded-lg input-item';
  newItem.innerHTML = `
    <input
      type="hidden"
      name="${inputName}"
      value="${escapeHtml(value)}"
    />
    <span class="text-sm text-gray-700">${escapeHtml(value)}</span>
    <button
      type="button"
      class="inline-flex items-center justify-center px-2 py-1 rounded border border-red-300 bg-red-50 text-red-700 hover:bg-red-100 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 transition-colors remove-input-btn"
    >
      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
      </svg>
    </button>
  `;

  // Check if this is the first item
  const noItemsMessage = container.querySelector('.text-gray-500.italic');
  if (noItemsMessage) {
    noItemsMessage.remove();
  }

  container.appendChild(newItem);
  inputField.value = '';
  inputField.focus();
}

/**
 * Remove an item from a multi-input list
 * @param {HTMLElement} button - The remove button that was clicked
 */
function removeInput(button) {
  const item = button.closest('.input-item');
  if (!item) return;

  const container = item.closest('[id*="_container"]');
  if (!container) return;

  item.remove();

  // Check if container is now empty
  const items = container.querySelectorAll('.input-item');
  if (items.length === 0) {
    const noItemsDiv = document.createElement('div');
    noItemsDiv.className = 'text-sm text-gray-500 italic py-2';
    noItemsDiv.textContent = 'No items added yet';
    container.appendChild(noItemsDiv);
  }
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Initialize client form functionality
 */
export function initClientForm(root = document) {
  // Set up event delegation for add/remove buttons
  root.addEventListener('click', function(e) {
    const addBtn = e.target.closest('.add-input-btn');
    const removeBtn = e.target.closest('.remove-input-btn');

    if (addBtn) {
      e.preventDefault();
      const inputName = addBtn.getAttribute('data-input-name');
      if (inputName) {
        addInput(inputName);
      }
    }

    if (removeBtn) {
      e.preventDefault();
      removeInput(removeBtn);
    }
  });

  // Allow Enter key to add items
  root.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      const input = e.target.closest('input[id*="_input"]');
      if (input) {
        e.preventDefault();
        const inputName = input.id.replace('_input', '');
        addInput(inputName);
      }
    }
  });
}
