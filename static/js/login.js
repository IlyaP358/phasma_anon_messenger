console.log('[Init] Login page loaded');

// Проверяем есть ли уже валидная сессия в cookie
function verifyExistingSession() {
    console.log('[Login] Checking for existing session...');

    fetch("/verify-session", {
        credentials: 'include'  // Отправляем cookies
    })
        .then(response => {
            if (response.status === 200) {
                console.log('[Login] Session is valid, redirecting to groups');
                window.location.href = '/groups';
            } else {
                console.log('[Login] Session is invalid or expired');
            }
        })
        .catch(err => {
            console.warn('[Login] Could not verify session:', err);
        });
}

// Проверяем сессию при загрузке страницы
verifyExistingSession();

document.getElementById('login-form').addEventListener('submit', function (e) {
    e.preventDefault();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const errorDiv = document.getElementById('error-msg');
    const submitBtn = document.getElementById('submit-btn');

    console.log('[Login] Form submitted for user:', username);

    if (!username || !password) {
        errorDiv.innerHTML = '<div class="error">Please enter username and password</div>';
        return;
    }

    errorDiv.innerHTML = '<div class="loading">Logging in...</div>';
    submitBtn.disabled = true;

    const formData = new URLSearchParams();
    formData.append('user', username);
    formData.append('password', password);

    console.log('[Login] Sending POST request to /login');

    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: formData.toString(),
        credentials: 'include'  // Важно! Браузер сохранит HttpOnly cookie
    })
        .then(response => {
            console.log('[Login] Response status:', response.status);

            if (!response.ok) {
                return response.json().then(data => {
                    console.error('[Login] Server error:', data);
                    throw new Error(data.error || 'Login failed');
                });
            }
            return response.json();
        })
        .then(data => {
            console.log('[Login] Response received');

            if (data.success && data.token) {
                console.log('[Login] Success! HttpOnly cookie set by server');

                localStorage.setItem('username', data.username);

                console.log('[Login] Saved username to localStorage:', data.username);
                console.log('[Login] Token stored in HttpOnly cookie by server (not accessible from JS)');

                // Очищаем форму
                document.getElementById('username').value = '';
                document.getElementById('password').value = '';

                errorDiv.innerHTML = '<div class="loading">✓ Login successful! Redirecting...</div>';

                // Редирект на страницу групп
                console.log('[Login] Redirecting to:', data.redirect || '/groups');
                setTimeout(() => {
                    window.location.href = data.redirect || '/groups';
                }, 500);
            } else {
                console.error('[Login] Invalid response:', data);
                throw new Error('Invalid response from server');
            }
        })
        .catch(error => {
            console.error('[Login] Error caught:', error.message);
            errorDiv.innerHTML = '<div class="error">✗ ' + error.message + '</div>';
            submitBtn.disabled = false;
        });
});
