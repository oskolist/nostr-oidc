document.body.addEventListener('htmx:configRequest', function(evt) {
  console.log({ evt })
  if (evt.detail.path.includes("admin")) {
    // Dynamically set the Authorization header (e.g., from localStorage)
    const token = localStorage.getItem('oidc_access_token');
    if (token) {
      evt.detail.headers['Authorization'] = `Bearer ${token}`;
    }
  }
});
