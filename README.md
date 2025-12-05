<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Sign In - Car Rental</title>
  <link rel="stylesheet" href="styles.css" /> 
</head>
<body>
  <main class="card" aria-labelledby="loginTitle">
    <h2 id="loginTitle">Sign in</h2>

    <form id="login-form" novalidate>
      <input type="hidden" id="returnTo" name="returnTo" value="">

      <label for="email">Email
        <input id="email" name="email" type="email" required autocomplete="email" />
      </label>

      <label for="password">Password
        <input id="password" name="password" type="password" required autocomplete="current-password" />
      </label>

      <button type="submit" id="submitBtn">Log In</button>

      <div id="message" role="status" aria-live="polite"></div>

      <p class="note">No account? <a class="muted-link" href="signup.html">Create one</a></p>
    </form>
  </main>

  <script>
    // NOTE: This client-side logic is for demonstration only and is NOT secure for real applications.
    
    // --- Return-to handling ---
    function getQueryParam(name) {
      return new URLSearchParams(window.location.search).get(name);
    }
    function isSafeRedirect(target) {
      if (!target || typeof target !== 'string') return false;
      if (target.startsWith('//')) return false;
      if (target.startsWith('/')) return true;
      return false;
    }
    const DEFAULT_REDIRECT = '/dashboard.html';

    (function initReturnTo() {
      const q = getQueryParam('returnTo');
      const s = sessionStorage.getItem('returnTo') || '';
      const chosen = (s && isSafeRedirect(s)) ? s : (q && isSafeRedirect(q) ? q : '');
      if (chosen) {
        document.getElementById('returnTo').value = chosen;
        sessionStorage.setItem('returnTo', chosen);
      }
    })();

    // --- Crypto helpers (PBKDF2 via SubtleCrypto) ---
    // This function hashes the password using a salt for security demo
    async function deriveKeyBase64(password, saltBase64, iterations = 150000) {
      const enc = new TextEncoder();
      const passKey = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
      );
      const salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
      const derived = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
        passKey,
        256
      );
      return btoa(String.fromCharCode(...new Uint8Array(derived)));
    }

    // --- Local user storage helpers (DEMO ONLY) ---
    const USERS_KEY = 'car_rental_demo_users_v1';
    function loadUsers() {
      try { return JSON.parse(localStorage.getItem(USERS_KEY) || '{}'); } catch (e) { return {}; }
    }

    // --- UI & login handler ---
    const form = document.getElementById('login-form');
    const msg = document.getElementById('message');
    const submitBtn = document.getElementById('submitBtn');

    function showMessage(text, isError = true) {
      msg.textContent = text || '';
      msg.className = isError ? 'error' : 'success';
    }

    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      showMessage('');
      submitBtn.disabled = true;
      submitBtn.textContent = 'Signing in...';

      const email = document.getElementById('email').value.trim().toLowerCase();
      const password = document.getElementById('password').value;
      const returnTo = document.getElementById('returnTo').value;

      if (!email || !password) {
        showMessage('Please fill both email and password.');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Log In';
        return;
      }

      // 1. Try SERVER-SIDE login first (This requires a backend server at the /login path)
      try {
        const resp = await fetch('/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({ email, password, returnTo })
        });

        if (resp.ok) {
          let data = null;
          try { data = await resp.json(); } catch (e) {}
          const serverDest = (data && data.redirectTo && isSafeRedirect(data.redirectTo)) ? data.redirectTo : null;
          const dest = serverDest || (isSafeRedirect(returnTo) ? returnTo : DEFAULT_REDIRECT);
          sessionStorage.removeItem('returnTo');
          window.location.href = dest;
          return;
        }

        // Handle server error response
        let errText = 'Login failed. Check your credentials.';
        try {
          const j = await resp.json();
          if (j && j.error) errText = j.error;
        } catch (e) { if (resp.statusText) errText = resp.statusText; }
        showMessage(errText);
        
      } catch (serverErr) {
        // 2. Fall back to CLIENT-SIDE DEMO login if server fails (e.g., when hosted on GitHub Pages)
        console.warn('Server login failed or not available, using client-side demo check.', serverErr);
        
        try {
          const users = loadUsers();
          const record = users[email];
          if (!record) {
            showMessage('No account found for that email. Create one first.');
            submitBtn.disabled = false;
            submitBtn.textContent = 'Log In';
            return;
          }
          const derived = await deriveKeyBase64(password, record.salt, 150000);
          if (derived !== record.passwordHash) {
            showMessage('Invalid email or password.');
            submitBtn.disabled = false;
            submitBtn.textContent = 'Log In';
            return;
          }
          // success: mark session and redirect
          sessionStorage.setItem('car_rental_demo_user', email);
          const dest = isSafeRedirect(returnTo) ? returnTo : DEFAULT_REDIRECT;
          sessionStorage.removeItem('returnTo');
          window.location.href = dest;
          return;
        } catch (e) {
          console.error('Client login error:', e);
          showMessage('Login failed (client). See console for details.');
        }
      }
      
      // Reset button state if login attempt failed
      submitBtn.disabled = false;
      submitBtn.textContent = 'Log In';
    });
  </script>
</body>
</html>
