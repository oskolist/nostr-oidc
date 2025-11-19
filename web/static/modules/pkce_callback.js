(async function() {
    const configElement = document.getElementById('token-config');
    const config = JSON.parse(configElement.textContent);


    function showNotification(message, type = 'info') {
        const container = document.getElementById('notifications-container');
        const notification = document.createElement('div');
        notification.className = `p-3 rounded-md text-sm font-medium ${type === 'error' ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200' : type === 'success' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'}`;
        notification.innerText = message;
        container.appendChild(notification);
        setTimeout(() => notification.remove(), 5000);
    }

    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    // const receivedNonce = urlParams.get('nonce');
    // const storedNonce = localStorage.getItem('nonce');
    const nonce = localStorage.getItem('pkce_code_verifier');
    const redirect_uri = localStorage.getItem('pkce_redirect_uri');
    const client_id = localStorage.getItem('pkce_client_id');

    document.getElementById('auth-code').innerText = code || 'N/A';
    // document.getElementById('nonce-value').innerText = receivedNonce || 'N/A';

    if (!code) {
        showNotification('Error: Authorization code not found in URL.', 'error');
        document.getElementById('status-message').innerText = 'Error: Authorization code not found.';
        return;
    }

    // if (!receivedNonce) {
    //     showNotification('Error: Nonce not found in URL.', 'error');
    //     document.getElementById('status-message').innerText = 'Error: Nonce not found.';
    //     return;
    // }

    // if (receivedNonce !== storedNonce) {
    //     showNotification('Error: Nonce mismatch. Possible CSRF attack.', 'error');
    //     document.getElementById('status-message').innerText = 'Error: Nonce mismatch. Possible CSRF attack.';
    //     console.error('Nonce mismatch:', { receivedNonce, storedNonce });
    //     return;
    // }

    if (!nonce) {
        showNotification('Error: PKCE code_verifier not found in storage. Session expired or invalid flow.', 'error');
        document.getElementById('status-message').innerText = 'Error: PKCE code_verifier not found in storage.';
        console.error('PKCE Error: code_verifier missing.');
        return;
    }

    if (!redirect_uri) {
        showNotification('Error: redirect_uri not found in storage. Cannot complete token exchange.', 'error');
        document.getElementById('status-message').innerText = 'Error: redirect_uri not found in storage.';
        console.error('PKCE Error: redirect_uri missing.');
        return;
    }

    if (!client_id) {
        showNotification('Error: client_id not found in storage. Cannot complete token exchange.', 'error');
        document.getElementById('status-message').innerText = 'Error: client_id not found in storage.';
        console.error('PKCE Error: client_id missing.');
        return;
    }

    showNotification('Attempting to exchange authorization code for tokens...', 'info');
    document.getElementById('status-message').innerText = 'Exchanging code for tokens...';

    try {
        const response = await fetch(config.tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: redirect_uri,
                client_id: client_id,
                code_verifier: nonce,
            }).toString(),
        });

        const data = await response.json();

        if (response.ok) {
            showNotification('Token exchange successful!', 'success');
            document.getElementById('status-message').innerText = 'Token exchange successful!';
            document.getElementById('token-response').innerText = JSON.stringify(data, null, 2);
            // Clear PKCE related items from localStorage after successful exchange
            localStorage.removeItem('pkce_code_verifier');
            localStorage.removeItem('pkce_nonce');
            localStorage.removeItem('pkce_redirect_uri');
            localStorage.removeItem('pkce_client_id');
            // Set the cookie (adjust expiration, path, etc., as needed)
            if (data.id_token) {
                localStorage.setItem('oidc_access_token', data.id_token);
            }

            // Start countdown and redirect
            startRedirectCountdown();

        } else {
            showNotification(`Error exchanging tokens: ${data.error_description || data.error || response.statusText}`, 'error');
            document.getElementById('status-message').innerText = `Error: ${data.error || response.statusText}`;
            document.getElementById('token-response').innerText = JSON.stringify(data, null, 2);
            console.error('Token exchange failed:', data);
        }
    } catch (error) {
        showNotification(`Network or server error during token exchange: ${error.message}`, 'error');
        document.getElementById('status-message').innerText = 'Error: Network or server issue.';
        document.getElementById('token-response').innerText = error.message;
        console.error('Token exchange error:', error);
    }
    function startRedirectCountdown() {
        const countdownElement = document.getElementById('redirect-countdown');
        if (!countdownElement) return;

        countdownElement.classList.remove('hidden');
        let remainingSeconds = 3;

        countdownElement.innerText = `Redirecting in ${remainingSeconds} seconds...`;

        const intervalId = setInterval(() => {
            remainingSeconds -= 1;
            if (remainingSeconds > 0) {
                countdownElement.innerText = `Redirecting in ${remainingSeconds} seconds...`;
            } else {
                clearInterval(intervalId);
                countdownElement.innerText = 'Redirecting now...';
                window.location.href = '/admin';
            }
        }, 1000);
    }
})()
