console.log('[Init] Register page loaded');

const USERNAME_MIN = 3;
const USERNAME_MAX = 32;
const PASSWORD_MIN = 8;
const PASSWORD_MAX = 128;

const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const messageBox = document.getElementById('message-box');
const submitBtn = document.getElementById('submit-btn');
const usernameReqs = document.getElementById('username-requirements');
const passwordReqs = document.getElementById('password-requirements');
const confirmPasswordInput = document.getElementById('confirm_password');
const confirmPasswordError = document.getElementById('confirm-password-error');

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

// Проверка требований username в реальном времени
usernameInput.addEventListener('input', function () {
    const username = this.value.trim();
    let html = '';

    const validLength = username.length >= USERNAME_MIN && username.length <= USERNAME_MAX;
    html += `<div class="${validLength ? 'requirement-met' : 'requirement-unmet'}">
        ${validLength ? '✓' : '✗'} Length: ${username.length}/${USERNAME_MIN}-${USERNAME_MAX} characters
      </div>`;

    const validChars = /^[a-zA-Z0-9_-]*$/.test(username);
    html += `<div class="${validChars ? 'requirement-met' : 'requirement-unmet'}">
        ${validChars ? '✓' : '✗'} Only letters, numbers, underscores, hyphens
      </div>`;

    usernameReqs.innerHTML = html;
});

// Проверка требований password в реальном времени
passwordInput.addEventListener('input', function () {
    const password = this.value;
    let html = '';

    const validLength = password.length >= PASSWORD_MIN && password.length <= PASSWORD_MAX;
    html += `<div class="${validLength ? 'requirement-met' : 'requirement-unmet'}">
        ${validLength ? '✓' : '✗'} Length: ${password.length}/${PASSWORD_MIN}-${PASSWORD_MAX} characters
      </div>`;

    passwordReqs.innerHTML = html;
});

const modal = document.getElementById('captchaModal');
const closeBtn = document.getElementsByClassName("close")[0];
const refreshBtn = document.getElementById('refresh-captcha');
const verifyBtn = document.getElementById('verify-btn');
const captchaBox = document.getElementById('captcha-box');
const captchaInput = document.getElementById('captcha-input');
const modalError = document.getElementById('modal-error');

function loadCaptcha() {
    captchaBox.innerHTML = '<div style="color:#000">Loading...</div>';
    fetch('/captcha-image')
        .then(response => response.text())
        .then(html => {
            captchaBox.innerHTML = html;
        })
        .catch(err => {
            console.error('Failed to load captcha', err);
            captchaBox.innerHTML = 'Error loading captcha';
        });
}

closeBtn.onclick = function () {
    modal.style.display = "none";
    submitBtn.disabled = false;
}

window.onclick = function (event) {
    if (event.target == modal) {
        modal.style.display = "none";
        submitBtn.disabled = false;
    }
}

refreshBtn.onclick = function () {
    loadCaptcha();
    captchaInput.value = '';
    captchaInput.focus();
}

document.getElementById('register-form').addEventListener('submit', function (e) {
    e.preventDefault();

    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    console.log('[Register] Form submitted for user:', username);

    // Валидация на клиенте
    if (!username) {
        messageBox.innerHTML = '<div class="error">✗ Username cannot be empty</div>';
        return;
    }

    if (username.length < USERNAME_MIN) {
        messageBox.innerHTML = `<div class="error">✗ Username must be at least ${USERNAME_MIN} characters</div>`;
        return;
    }

    if (username.length > USERNAME_MAX) {
        messageBox.innerHTML = `<div class="error">✗ Username must not exceed ${USERNAME_MAX} characters</div>`;
        return;
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
        messageBox.innerHTML = '<div class="error">✗ Username can only contain letters, numbers, underscores, and hyphens</div>';
        return;
    }

    if (!password) {
        messageBox.innerHTML = '<div class="error">✗ Password cannot be empty</div>';
        return;
    }

    if (password.length < PASSWORD_MIN) {
        messageBox.innerHTML = `<div class="error">✗ Password must be at least ${PASSWORD_MIN} characters</div>`;
        return;
    }

    if (password.length > PASSWORD_MAX) {
        messageBox.innerHTML = `<div class="error">✗ Password must not exceed ${PASSWORD_MAX} characters</div>`;
        return;
    }

    const confirmPassword = confirmPasswordInput.value;
    if (password !== confirmPassword) {
        messageBox.innerHTML = '<div class="error">✗ Passwords do not match</div>';
        confirmPasswordError.textContent = "Passwords do not match";
        return;
    } else {
        confirmPasswordError.textContent = "";
    }

    // Show Modal instead of submitting immediately
    modal.style.display = "block";
    loadCaptcha();
    captchaInput.value = '';
    modalError.style.display = 'none';
    captchaInput.focus();
});

verifyBtn.addEventListener('click', function () {
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const captcha = captchaInput.value.trim();

    if (!captcha) {
        modalError.textContent = "Please enter the captcha code";
        modalError.style.display = 'block';
        return;
    }

    modalError.style.display = 'none';
    verifyBtn.disabled = true;
    verifyBtn.textContent = "Verifying...";

    console.log('[Register] Sending POST request to /register');

    fetch('/register', {
        method: 'POST',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            user: username,
            password: password,
            captcha: captcha
        }),
        credentials: 'include'
    })
        .then(response => {
            console.log('[Register] Response status:', response.status);
            return response.json().then(data => {
                return { status: response.status, data: data };
            });
        })
        .then(result => {
            if (result.status === 201 || result.status === 200) {
                console.log('[Register] Success! Account created for:', username);
                modal.style.display = "none";
                messageBox.innerHTML = '<div class="success">✓ ' + result.data.message + ' Redirecting to login...</div>';

                usernameInput.value = '';
                passwordInput.value = '';
                usernameReqs.innerHTML = '';
                passwordReqs.innerHTML = '';

                setTimeout(() => {
                    window.location.href = '/login';
                }, 1500);
            } else {
                console.error('[Register] Server error:', result.data.error);
                // If captcha error, show in modal
                if (result.data.error && result.data.error.toLowerCase().includes('captcha')) {
                    modalError.textContent = result.data.error;
                    modalError.style.display = 'block';
                    verifyBtn.disabled = false;
                    verifyBtn.textContent = "VERIFY & CREATE";
                    loadCaptcha(); // Refresh captcha on failure
                    captchaInput.value = '';
                } else {
                    // Other errors (username taken etc) - close modal and show on main page
                    modal.style.display = "none";
                    messageBox.innerHTML = `<div class="error">✗ ${result.data.error}</div>`;
                    submitBtn.disabled = false;
                }
            }
        })
        .catch(error => {
            console.error('[Register] Error caught:', error.message);
            modal.style.display = "none";
            messageBox.innerHTML = '<div class="error">✗ An error occurred. Please try again.</div>';
            submitBtn.disabled = false;
        });
});
