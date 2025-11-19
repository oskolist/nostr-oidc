document.body.addEventListener('htmx:configRequest', function(evt) {
  if (evt.detail.path.includes("admin")) {
    // Dynamically set the Authorization header (e.g., from localStorage)
    const token = localStorage.getItem('oidc_access_token');
    if (token) {
      evt.detail.headers['Authorization'] = `Bearer ${token}`;
    }
  }
});

document.body.addEventListener('htmx:afterRequest', function(evt) {

  if (evt.detail?.pathInfo?.requestPath != evt.detail?.pathInfo?.responsePath) {
    window.location.href = evt.detail?.pathInfo?.responsePath;
    return
  }
});
