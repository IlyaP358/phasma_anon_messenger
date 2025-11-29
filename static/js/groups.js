let AUTH_TOKEN = null;
let CURRENT_USER = null;
let ONLINE_HEARTBEAT_INTERVAL = null;
let SESSIONS_UPDATE_INTERVAL = null;
let isUnloading = false;
let currentDeleteGroupId = null;
let lastMessageTimestamps = {};
let isFirstLoad = true;

const createModal = document.getElementById('create-modal');
const joinModal = document.getElementById('join-modal');
const deleteModal = document.getElementById('delete-modal');
const profileModal = document.getElementById('profile-modal');

// Auth & Init
function initAuth() {
    CURRENT_USER = localStorage.getItem('username');
    if (!CURRENT_USER) {
        window.location.href = '/login';
        return false;
    }
    document.getElementById('current-user').textContent = CURRENT_USER;

    // Load header avatar
    const headerAvatar = document.getElementById('header-avatar');
    if (headerAvatar) {
        headerAvatar.src = `/user/profile-pic/${CURRENT_USER}?t=${new Date().getTime()}`;
    }

    verifySessionWithServer();
    return true;
}

function verifySessionWithServer() {
    fetch("/verify-session", { credentials: 'include' })
        .then(response => {
            if (response.status === 401) { handleSessionExpired(); }
        })
        .catch(err => console.warn('Session check failed', err));
}

function handleSessionExpired() {
    isUnloading = true;
    clearInterval(ONLINE_HEARTBEAT_INTERVAL);
    clearInterval(SESSIONS_UPDATE_INTERVAL);
    alert('Your session has expired. Please login again.');
    localStorage.removeItem('username');
    window.location.href = '/login';
}

function getCurrentUser() { return CURRENT_USER; }

// Notification Permission Logic
document.getElementById('menu-enable-notifications').addEventListener('click', () => {
    if (!("Notification" in window)) {
        alert("This browser does not support desktop notification");
    } else if (Notification.permission === "granted") {
        alert("Notifications are already enabled!");
    } else if (Notification.permission !== "denied") {
        Notification.requestPermission().then(function (permission) {
            if (permission === "granted") {
                alert("Notifications enabled!");
            }
        });
    }
});

// Sessions
function formatTime(timestamp) {
    try { const date = new Date(timestamp * 1000); const now = new Date(); const diff = now - date; const minutes = Math.floor(diff / 60000); if (minutes < 1) return "just now"; if (minutes < 60) return minutes + "m ago"; const hours = Math.floor(diff / 3600000); if (hours < 24) return hours + "h ago"; return date.toLocaleDateString(); } catch (e) { return "unknown"; }
}
function formatDate(timestamp) {
    try { const date = new Date(timestamp * 1000); const hours = String(date.getHours()).padStart(2, '0'); const minutes = String(date.getMinutes()).padStart(2, '0'); return date.toLocaleDateString() + " " + hours + ":" + minutes; } catch (e) { return "unknown"; }
}

function loadSessions() {
    const user = getCurrentUser(); if (!user) return;
    fetch('/api/sessions/list', { credentials: 'include' })
        .then(r => r.status === 401 ? handleSessionExpired() : r.json())
        .then(data => { if (data) renderSessions(data.sessions); });
}

function renderSessions(sessions) {
    const list = document.getElementById('sessions-list');
    document.getElementById('sessions-total').textContent = sessions.length;
    if (!sessions || sessions.length === 0) { list.innerHTML = '<div class="empty-state">No sessions</div>'; return; }
    let html = '';
    sessions.forEach(session => {
        const isCurrent = session.is_current;
        const browserIcon = session.browser.includes('Chrome') ? '🔷' : session.browser.includes('Firefox') ? '🦊' : '🌐';
        const className = isCurrent ? 'session-item current' : 'session-item';
        html += `<div class="${className}" data-token="${session.token}">
          ${isCurrent ? '<div class="session-button current-badge">This Device</div>' : ''}
          <div class="session-browser">${browserIcon} ${session.browser}</div>
          <div class="session-os">${session.os}</div>
          <div class="session-created">Created: ${formatDate(session.created_at)}</div>
          <div class="session-last-activity">Active: ${formatTime(session.last_activity)}</div>
          <div class="session-actions"><button class="session-button btn-terminate" data-token="${session.token}">${isCurrent ? 'Exit' : 'Terminate'}</button></div>
        </div>`;
    });
    list.innerHTML = html;
    document.querySelectorAll('.btn-terminate').forEach(btn => {
        btn.addEventListener('click', (e) => { e.stopPropagation(); terminateSession(btn.getAttribute('data-token')); });
    });
}

function terminateSession(sessionToken) {
    const btn = document.querySelector(`button[data-token="${sessionToken}"]`);
    const isCurrent = btn && btn.closest('.session-item').classList.contains('current');
    if (!confirm(isCurrent ? 'Exit this session?' : 'Terminate this session?')) return;
    fetch('/api/sessions/' + sessionToken + '/terminate', { method: 'POST', credentials: 'include' })
        .then(r => r.status === 401 ? handleSessionExpired() : r.json())
        .then(data => {
            if (isCurrent) {
                isUnloading = true; localStorage.removeItem('username'); window.location.href = '/login';
            } else { loadSessions(); }
        });
}

document.getElementById('btn-terminate-all').addEventListener('click', () => {
    if (!confirm('Terminate all other sessions?')) return;
    fetch('/api/sessions/terminate-all', { method: 'POST', credentials: 'include' })
        .then(r => r.status === 401 ? handleSessionExpired() : r.json())
        .then(() => { loadSessions(); alert('All other sessions terminated'); });
});

// Heartbeat
function sendOnlineHeartbeat() { fetch('/api/user/online', { method: 'POST', credentials: 'include' }); }
function startOnlineHeartbeat() { sendOnlineHeartbeat(); ONLINE_HEARTBEAT_INTERVAL = setInterval(sendOnlineHeartbeat, 20000); }

// Modals (Create/Join/Delete)
document.getElementById('btn-create').addEventListener('click', () => { createModal.classList.add('active'); });
document.getElementById('close-create').addEventListener('click', () => { createModal.classList.remove('active'); });
document.getElementById('btn-cancel-create').addEventListener('click', () => { createModal.classList.remove('active'); });
document.getElementById('btn-join').addEventListener('click', () => { joinModal.classList.add('active'); });
document.getElementById('close-join').addEventListener('click', () => { joinModal.classList.remove('active'); });
document.getElementById('btn-cancel-join').addEventListener('click', () => { joinModal.classList.remove('active'); });
document.getElementById('close-delete').addEventListener('click', () => { deleteModal.classList.remove('active'); });
document.getElementById('btn-cancel-delete').addEventListener('click', () => { deleteModal.classList.remove('active'); });

// Group Actions
document.getElementById('btn-submit-create').addEventListener('click', () => {
    const name = document.getElementById('create-name').value.trim();
    const password = document.getElementById('create-password').value;
    const rootPassword = document.getElementById('create-root-password').value;
    const maxMembers = parseInt(document.getElementById('create-max-members').value);
    const groupType = document.querySelector('input[name="create-type"]:checked').value;
    const errorDiv = document.getElementById('create-error');

    errorDiv.innerHTML = '';

    if (!name || !rootPassword) {
        errorDiv.innerHTML = '<div class="error">Name and Root Password are required</div>';
        return;
    }

    errorDiv.innerHTML = '<div class="loading">Creating group...</div>';

    fetch('/api/groups/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, password, root_password: rootPassword, max_members: maxMembers, group_type: groupType }),
        credentials: 'include'
    })
        .then(r => r.json())
        .then(d => {
            if (d.success) {
                errorDiv.innerHTML = '<div class="success">✓ Group created!</div>';
                loadGroups();
                setTimeout(() => {
                    createModal.classList.remove('active');
                    document.getElementById('create-name').value = '';
                    document.getElementById('create-password').value = '';
                    document.getElementById('create-root-password').value = '';
                    errorDiv.innerHTML = '';
                }, 1000);
            } else {
                errorDiv.innerHTML = '<div class="error">' + d.error + '</div>';
            }
        })
        .catch(err => {
            errorDiv.innerHTML = '<div class="error">Failed to create group</div>';
        });
});

document.getElementById('btn-submit-join').addEventListener('click', () => {
    const code = document.getElementById('join-code').value.trim().toUpperCase();
    const password = document.getElementById('join-password').value;
    const errorDiv = document.getElementById('join-error');

    errorDiv.innerHTML = '';

    if (!code) {
        errorDiv.innerHTML = '<div class="error">Please enter group code</div>';
        return;
    }

    errorDiv.innerHTML = '<div class="loading">Joining...</div>';

    fetch('/api/groups/join', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ group_code: code, password }),
        credentials: 'include'
    })
        .then(r => r.json())
        .then(d => {
            if (d.success) {
                errorDiv.innerHTML = '<div class="success">✓ Joined!</div>';
                loadGroups();
                setTimeout(() => {
                    joinModal.classList.remove('active');
                    document.getElementById('join-code').value = '';
                    document.getElementById('join-password').value = '';
                    errorDiv.innerHTML = '';
                }, 1000);
            } else {
                errorDiv.innerHTML = '<div class="error">' + d.error + '</div>';
            }
        })
        .catch(err => {
            errorDiv.innerHTML = '<div class="error">Failed to join group</div>';
        });
});

function loadGroups() {
    // Add timestamp to prevent caching
    fetch('/api/groups/list?t=' + Date.now(), { credentials: 'include' })
        .then(r => r.status === 401 ? handleSessionExpired() : r.json())
        .then(data => { if (data) renderGroups(data.groups); });
}

function renderGroups(groups) {
    const list = document.getElementById('groups-list');
    if (!groups || groups.length === 0) { list.innerHTML = '<div class="empty-state">No groups yet.</div>'; return; }

    // Client-side sort fallback (just in case)
    groups.sort((a, b) => b.last_message_at - a.last_message_at);

    let html = '';
    groups.forEach(group => {
        const isCreator = group.role === 'creator';

        let badgeHtml = '';
        if (group.unread_count > 0) {
            const countText = group.unread_count > 99 ? '99+' : group.unread_count;
            badgeHtml = `<span class="unread-badge">${countText}</span>`;
        }

        html += `<div class="group-item">
          <div class="group-name-container">
              <div class="group-name">${escapeHtml(group.name)}</div>
              ${badgeHtml}
          </div>
          <div class="group-code">#${group.code}</div>
          <div class="group-info">👤 ${isCreator ? '(Creator)' : '(Member)'}</div>
          <div class="group-buttons">
            <button class="btn btn-enter" data-group-id="${group.id}">Enter</button>
            ${isCreator ? '<button class="btn btn-danger btn-delete" data-group-id="' + group.id + '">Delete</button>' : ''}
          </div>
        </div>`;
    });
    list.innerHTML = html;
    document.querySelectorAll('.btn-enter').forEach(btn => btn.addEventListener('click', (e) => { e.stopPropagation(); window.location.href = '/group/' + btn.getAttribute('data-group-id') + '/chat'; }));
    document.querySelectorAll('.btn-delete').forEach(btn => btn.addEventListener('click', (e) => { e.stopPropagation(); currentDeleteGroupId = btn.getAttribute('data-group-id'); deleteModal.classList.add('active'); }));

    // Check for new messages
    let hasNewMessage = false;
    groups.forEach(group => {
        const lastTime = lastMessageTimestamps[group.id] || 0;
        if (group.last_message_at > lastTime) {
            if (!isFirstLoad && lastTime > 0) {
                hasNewMessage = true;
            }
            lastMessageTimestamps[group.id] = group.last_message_at;
        }
    });

    if (hasNewMessage) {
        playNotificationSound();
    }

    if (usernameDisplay) {
        usernameDisplay.textContent = `Logged in as: ${username}`;
        // Update header avatar
        const headerAvatar = document.getElementById('header-avatar');
        if (headerAvatar) {
            headerAvatar.src = `/user/profile-pic/${username}?t=${new Date().getTime()}`;
        }
    }
    isFirstLoad = false;
}

function playNotificationSound() {
    const audio = document.getElementById('notification-sound');
    if (audio) {
        audio.play().catch(e => console.log('Audio play failed (user interaction needed?):', e));
    }
}

document.getElementById('btn-confirm-delete').addEventListener('click', () => {
    const password = document.getElementById('delete-password').value;
    const errorDiv = document.getElementById('delete-error');

    errorDiv.innerHTML = '';

    if (!password) {
        errorDiv.innerHTML = '<div class="error">Password required</div>';
        return;
    }

    errorDiv.innerHTML = '<div class="loading">Deleting...</div>';

    fetch('/api/groups/' + currentDeleteGroupId + '/delete', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ root_password: password }), credentials: 'include'
    })
        .then(r => r.json())
        .then(d => {
            if (d.success) {
                errorDiv.innerHTML = '<div class="success">✓ Deleted</div>';
                loadGroups();
                setTimeout(() => {
                    deleteModal.classList.remove('active');
                    document.getElementById('delete-password').value = '';
                    errorDiv.innerHTML = '';
                }, 1000);
            } else {
                errorDiv.innerHTML = '<div class="error">' + d.error + '</div>';
            }
        })
        .catch(err => {
            errorDiv.innerHTML = '<div class="error">Failed to delete</div>';
        });
});

// Escape HTML
function escapeHtml(text) { const div = document.createElement('div'); div.textContent = text; return div.innerHTML; }

// Menu Logic
const btnMenu = document.getElementById('btn-menu');
const userMenuDropdown = document.getElementById('user-menu-dropdown');
document.addEventListener('click', (e) => { if (!btnMenu.contains(e.target) && !userMenuDropdown.contains(e.target)) userMenuDropdown.classList.remove('active'); });
btnMenu.addEventListener('click', () => userMenuDropdown.classList.toggle('active'));

document.getElementById('menu-exit').addEventListener('click', () => {
    isUnloading = true; fetch('/logout', { method: 'POST', credentials: 'include' }).finally(() => { localStorage.removeItem('username'); window.location.href = '/login'; });
});

// Account Deletion Logic
const deleteAccountModal = document.getElementById('delete-account-modal');
const deleteAccountError = document.getElementById('delete-account-error');

document.getElementById('menu-delete').addEventListener('click', () => {
    document.getElementById('delete-username-display').textContent = CURRENT_USER;
    deleteAccountModal.classList.add('active');
    userMenuDropdown.classList.remove('active');
    // Close profile modal to avoid UI collision
    profileModal.classList.remove('active');
});

// Profile Settings Logic
const profilePicInput = document.getElementById('profile-pic-input');
const profilePicPreview = document.getElementById('profile-pic-preview');
const profileError = document.getElementById('profile-error');

document.getElementById('menu-profile-settings').addEventListener('click', () => {
    document.getElementById('profile-username-display').textContent = CURRENT_USER;
    // Load current profile pic
    profilePicPreview.src = `/user/profile-pic/${CURRENT_USER}?t=${Date.now()}`;
    profileModal.classList.add('active');
    userMenuDropdown.classList.remove('active');
});

document.getElementById('close-profile').addEventListener('click', () => {
    profileModal.classList.remove('active');
    profileError.innerHTML = '';
});

document.getElementById('btn-close-profile').addEventListener('click', () => {
    profileModal.classList.remove('active');
    profileError.innerHTML = '';
});

document.querySelector('.profile-pic-overlay').addEventListener('click', () => {
    profilePicInput.click();
});

profilePicInput.addEventListener('change', function () {
    if (this.files && this.files[0]) {
        const file = this.files[0];

        // Basic validation
        if (file.size > 10 * 1024 * 1024) {
            profileError.innerHTML = '<div class="error">File too large (max 10MB)</div>';
            return;
        }

        // Upload immediately (or we could show preview then upload, but user asked for "crop if user wants" - for now simple upload)
        uploadProfilePic(file);
    }
});

function uploadProfilePic(file) {
    profileError.innerHTML = '<div class="loading">Uploading...</div>';

    const formData = new FormData();
    formData.append('file', file);

    fetch('/api/user/profile-pic', {
        method: 'POST',
        body: formData,
        credentials: 'include'
    })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                profileError.innerHTML = '<div class="success">Profile picture updated!</div>';
                // Update preview
                profilePicPreview.src = `/user/profile-pic/${CURRENT_USER}?t=${Date.now()}`;
                // Also update any other instances on the page if we add them
            } else {
                profileError.innerHTML = '<div class="error">' + (data.error || 'Upload failed') + '</div>';
            }
        })
        .catch(err => {
            console.error(err);
            profileError.innerHTML = '<div class="error">Upload failed</div>';
        });
}

document.getElementById('close-delete-account').addEventListener('click', () => {
    deleteAccountModal.classList.remove('active');
    document.getElementById('delete-account-password').value = '';
    deleteAccountError.textContent = '';
});

document.getElementById('btn-cancel-delete-account').addEventListener('click', () => {
    deleteAccountModal.classList.remove('active');
    document.getElementById('delete-account-password').value = '';
    deleteAccountError.textContent = '';
});

document.getElementById('btn-confirm-delete-account').addEventListener('click', () => {
    const password = document.getElementById('delete-account-password').value;
    if (!password) {
        deleteAccountError.innerHTML = '<div class="error">Please enter your password</div>';
        return;
    }

    if (!confirm("FINAL WARNING: Are you absolutely sure? This cannot be undone.")) {
        return;
    }

    deleteAccountError.innerHTML = '<div class="loading">Deleting account...</div>';

    fetch('/api/user/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: password }),
        credentials: 'include'
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                isUnloading = true;
                localStorage.removeItem('username');
                alert('Account deleted successfully. Goodbye.');
                window.location.href = '/register';
            } else {
                deleteAccountError.innerHTML = `<div class="error">${data.error || 'Failed to delete account'}</div>`;
            }
        })
        .catch(err => {
            console.error('Error deleting account:', err);
            deleteAccountError.innerHTML = '<div class="error">Network error. Please try again.</div>';
        });
});

// Init
if (initAuth()) {
    loadGroups(); loadSessions(); startOnlineHeartbeat();
    loadGroups(); loadSessions(); startOnlineHeartbeat();
    setInterval(loadGroups, 60000); setInterval(loadSessions, 5000); setInterval(verifySessionWithServer, 30000);

    // Initialize SSE for real-time updates
    initSSE();

    // Initialize Push Notifications
    initPushNotifications();

    // Refresh on focus/visibility
    window.addEventListener('focus', loadGroups);
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) loadGroups();
    });
}

// ========== PUSH NOTIFICATIONS ==========
async function initPushNotifications() {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
        console.log('Push messaging is not supported');
        return;
    }

    try {
        // Register SW
        const registration = await navigator.serviceWorker.register('/static/service-worker.js');
        console.log('Service Worker registered:', registration);

        // Request permission
        const permission = await Notification.requestPermission();
        if (permission !== 'granted') {
            console.log('Notification permission denied');
            return;
        }

        // Get VAPID key
        const response = await fetch('/api/vapid-public-key');
        const data = await response.json();
        const vapidPublicKey = data.publicKey;

        if (!vapidPublicKey) {
            console.error('No VAPID public key found');
            return;
        }

        const convertedVapidKey = urlBase64ToUint8Array(vapidPublicKey);

        // Subscribe
        const subscription = await registration.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: convertedVapidKey
        });

        // ALWAYS send to server to ensure it's up to date and refresh last_used
        await fetch('/api/subscribe', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                subscription_info: subscription
            })
        });

        console.log('Push notification subscription updated/verified');

    } catch (error) {
        console.error('Push notification error:', error);
    }
}


// ========== SSE (Real-time Updates) ==========
function initSSE() {
    if (!window.EventSource) {
        console.log("SSE not supported");
        return;
    }

    const eventSource = new EventSource("/api/user/events");

    eventSource.onmessage = function (event) {
        const data = JSON.parse(event.data);
        if (data.type === 'ping') return;

        if (data.type === 'group_update') {
            console.log("Received group update:", data);
            // Reload groups to update unread counts and order
            loadGroups();
            // Play sound
            playNotificationSound();
        }
    };

    eventSource.onerror = function (err) {
        console.error("SSE Error:", err);
        eventSource.close();
        // Retry after 5 seconds
        setTimeout(initSSE, 5000);
    };
}

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
// Sidebar Toggle
const btnToggleSessions = document.getElementById('btn-toggle-sessions');
const sessionsSidebar = document.querySelector('.sessions-sidebar');

if (btnToggleSessions) {
    btnToggleSessions.addEventListener('click', (e) => {
        e.stopPropagation();
        sessionsSidebar.classList.toggle('active');
    });
}

document.addEventListener('click', (e) => {
    if (window.innerWidth <= 768) {
        if (sessionsSidebar && sessionsSidebar.classList.contains('active') &&
            !sessionsSidebar.contains(e.target) &&
            e.target !== btnToggleSessions) {
            sessionsSidebar.classList.remove('active');
        }
    }
});
