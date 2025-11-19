document.addEventListener("DOMContentLoaded", function () {
    (function () {
        function dec2hex(dec) {
            return ('0' + dec.toString(16)).substr(-2)
        }

        function generateCodeVerifier() {
            var array = new Uint32Array(56 / 2);
            window.crypto.getRandomValues(array);
            return Array.from(array, dec2hex).join('');
        }

        function generateNonce() {
            var array = new Uint32Array(16);
            window.crypto.getRandomValues(array);
            return Array.from(array, dec2hex).join('');
        }

        function sha256(plain) {
            const encoder = new TextEncoder();
            const data = encoder.encode(plain);
            return window.crypto.subtle.digest('SHA-256', data);
        }

        function base64urlencode(a) {
            var str = "";
            var bytes = new Uint8Array(a);
            var len = bytes.byteLength;
            for (var i = 0; i < len; i++) {
                str += String.fromCharCode(bytes[i]);
            }
            return btoa(str)
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
        }

        async function generatePkceCodes() {
            // Load config from JSON script
            var configElement = document.getElementById('pkce-config');
            var config = JSON.parse(configElement.textContent);

            var code_verifier = generateCodeVerifier();
            const codeVerifier = document.getElementById('code_verifier')
            if (codeVerifier) {
                codeVerifier.innerText = code_verifier;
            }
            localStorage.setItem('pkce_code_verifier', code_verifier);

            var nonce = generateNonce();

            const nonceEl = document.getElementById('nonce');
            if (nonceEl) {
                nonceEl.innerText = nonce;
            }

            localStorage.setItem('pkce_nonce', nonce);

            var hashed = await sha256(code_verifier);
            var code_challenge = base64urlencode(hashed);
            const codeChallengeEl = document.getElementById('code_challenge');

            if (codeChallengeEl) {
                codeChallengeEl.innerText = code_challenge;
            }
            localStorage.setItem('pkce_code_challenge', code_challenge);

            localStorage.setItem('pkce_client_id', config.clientID);
            localStorage.setItem('pkce_redirect_uri', config.redirectURI);

            var authorizeURL = new URL(window.location.origin + '/authorize');
            authorizeURL.searchParams.append('response_type', 'code');
            authorizeURL.searchParams.append('client_id', config.clientID);
            authorizeURL.searchParams.append('redirect_uri', config.redirectURI);
            authorizeURL.searchParams.append('scope', config.scope);
            authorizeURL.searchParams.append('nonce', nonce);
            authorizeURL.searchParams.append('code_challenge', code_challenge);
            authorizeURL.searchParams.append('code_challenge_method', 'S256');

            localStorage.setItem('pkce_authorize_url', authorizeURL.toString());

            console.log('Code Verifier:', code_verifier);
            console.log('Code Challenge:', code_challenge);
            console.log('Nonce:', nonce);
            console.log('Authorization URL:', authorizeURL.toString());

            setTimeout(() => {
                window.location.href = authorizeURL.toString();
            }, 750)
        }

        generatePkceCodes();
    })();
});
