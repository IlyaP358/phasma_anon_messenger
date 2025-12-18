console.log('[Init] Login page loaded');

// Toggle Password Visibility
document.querySelectorAll('.toggle-password').forEach(button => {
    button.addEventListener('click', function () {
        const targetId = this.getAttribute('data-target');
        const input = document.getElementById(targetId);
        if (input) {
            if (input.type === "password") {
                input.type = "text";
                this.textContent = "🔒"; // Icon for hiding
            } else {
                input.type = "password";
                this.textContent = "👁️"; // Icon for showing
            }
        }
    });
});

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

                errorDiv.innerHTML = '<div class="loading">✓ Login successful! Setting up notifications...</div>';

                // Initialize push notifications BEFORE redirect (PWA fix)
                initPushNotificationsOnLogin().then(() => {
                    errorDiv.innerHTML = '<div class="loading">✓ Login successful! Redirecting...</div>';
                    console.log('[Login] Redirecting to:', data.redirect || '/groups');
                    setTimeout(() => {
                        window.location.href = data.redirect || '/groups';
                    }, 500);
                }).catch(err => {
                    console.warn('[Login] Push notification setup failed, continuing anyway:', err);
                    errorDiv.innerHTML = '<div class="loading">✓ Login successful! Redirecting...</div>';
                    console.log('[Login] Redirecting to:', data.redirect || '/groups');
                    setTimeout(() => {
                        window.location.href = data.redirect || '/groups';
                    }, 500);
                });
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

// ========== PUSH NOTIFICATION HELPERS ==========
function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding)
        .replace(/\-/g, '+')
        .replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

async function initPushNotificationsOnLogin() {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
        console.log('[Login] Push messaging not supported');
        return;
    }

    try {
        console.log('[Login] Registering service worker...');
        const registration = await navigator.serviceWorker.register('/static/service-worker.js');
        await navigator.serviceWorker.ready;
        console.log('[Login] Service worker ready');

        const permission = await Notification.requestPermission();
        if (permission !== 'granted') {
            console.log('[Login] Notification permission denied');
            return;
        }
        console.log('[Login] Notification permission granted');

        const response = await fetch('/api/vapid-public-key');
        const data = await response.json();
        const vapidPublicKey = data.publicKey;

        if (!vapidPublicKey) {
            console.error('[Login] No VAPID public key');
            return;
        }

        const convertedVapidKey = urlBase64ToUint8Array(vapidPublicKey);
        const subscription = await registration.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: convertedVapidKey
        });
        console.log('[Login] Push subscription created');

        await fetch('/api/subscribe', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ subscription_info: subscription }),
            credentials: 'include'
        });

        console.log('[Login] Push notification subscription completed successfully');
    } catch (error) {
        console.error('[Login] Push notification error:', error);
        throw error;
    }
}
