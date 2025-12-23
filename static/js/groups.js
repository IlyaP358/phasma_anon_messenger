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
const dmQrModal = document.getElementById('dm-qr-modal');

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
        const isDM = group.is_dm || false;

        let badgeHtml = '';
        if (group.unread_count > 0) {
            const countText = group.unread_count > 99 ? '99+' : group.unread_count;
            badgeHtml = `<span class="unread-badge">${countText}</span>`;
        }

        // Avatar for groups
        let avatarHtml = '';
        if (isDM && group.opponent_username) {
            avatarHtml = `<img src="/user/profile-pic/${group.opponent_username}" alt="Avatar" class="dm-avatar header-avatar" style="width: 40px; height: 40px; border-radius: 50%; margin-right: 10px; object-fit: cover;" onerror="this.style.display='none'">`;
        } else if (isDM) {
            avatarHtml = `<img src="/static/unknown_user_phasma_icon.png" alt="Avatar" class="dm-avatar header-avatar" style="width: 40px; height: 40px; border-radius: 50%; margin-right: 10px; object-fit: cover;">`;
        } else { // Group avatar
            avatarHtml = `<img src="/group/avatar/${group.id}" alt="Group Avatar" class="header-avatar" style="width: 32px; height: 32px; border-radius: 50%; margin-right: 8px; object-fit: cover; flex-shrink: 0;" onerror="this.style.display='none'">`;
        }

        // Settings gear icon for creators (top-right corner)
        let settingsIconHtml = '';
        if (isCreator && !isDM) {
            settingsIconHtml = `<button class="btn-settings-gear" data-group-id="${group.id}" data-group-type="${group.type || 'public'}" title="Settings">⚙️</button>`;
        }

        html += `<div class="group-item" data-group-id="${group.id}" style="position: relative; cursor: pointer;">
          ${settingsIconHtml}
          <div class="group-name-container" style="display: flex; align-items: center;">
              ${avatarHtml}
              <div style="flex: 1;">
                  <div class="group-name">${escapeHtml(group.name)}</div>
                  ${!isDM ? `<div class="group-code">#${group.code}</div>` : ''}
              </div>
              ${badgeHtml}
          </div>
          ${!isDM ? `<div class="group-info">👤 ${isCreator ? '(Creator)' : '(Member)'}</div>` : ''}
        </div>`;
    });
    list.innerHTML = html;

    // Make entire item clickable
    document.querySelectorAll('.group-item').forEach(item => {
        item.addEventListener('click', (e) => {
            // Ignore if clicked on settings gear
            if (e.target.closest('.btn-settings-gear')) return;
            window.location.href = '/group/' + item.getAttribute('data-group-id') + '/chat';
        });
    });

    // Settings Gear Icon Logic
    document.querySelectorAll('.btn-settings-gear').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const groupId = btn.getAttribute('data-group-id');
            const currentType = btn.getAttribute('data-group-type');
            openSettingsModal(groupId, currentType);
        });
    });



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

    // Update username display if element exists
    const usernameDisplay = document.getElementById('username-display');
    if (usernameDisplay) {
        // Username is stored globally or can be fetched from first group's data
        // For now, we'll skip this as it's not critical
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
if (profilePicPreview) {
    profilePicPreview.onerror = function() {
        this.src = '/static/unknown_user_phasma_icon.png';
    };
}
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

// DM QR Code Logic
const btnShowDmQr = document.getElementById('btn-show-dm-qr');
if (btnShowDmQr) {
    btnShowDmQr.addEventListener('click', () => {
        if (!dmQrModal) return;
        dmQrModal.classList.add('active');
        document.getElementById('dm-qr-loading').style.display = 'block';
        document.getElementById('dm-qr-content').style.display = 'none';

        fetch('/api/user/dm-invite', { credentials: 'include' })
            .then(r => r.json())
            .then(data => {
                document.getElementById('dm-qr-loading').style.display = 'none';
                document.getElementById('dm-qr-content').style.display = 'block';
                document.getElementById('dm-qr-img').src = data.qr_code;
                document.getElementById('dm-invite-link').value = data.invite_url;
            })
            .catch(err => {
                document.getElementById('dm-qr-loading').textContent = 'Failed to generate QR';
            });
    });
}

const closeDmQrBtn = document.getElementById('close-dm-qr');
if (closeDmQrBtn) {
    closeDmQrBtn.addEventListener('click', () => {
        dmQrModal.classList.remove('active');
    });
}

const btnCopyDmLink = document.getElementById('btn-copy-dm-link');
if (btnCopyDmLink) {
    btnCopyDmLink.addEventListener('click', () => {
        const link = document.getElementById('dm-invite-link');
        link.select();
        document.execCommand('copy');
        const oldText = btnCopyDmLink.textContent;
        btnCopyDmLink.textContent = '✓ Copied!';
        setTimeout(() => btnCopyDmLink.textContent = oldText, 2000);
    });
}

// Group Avatar Logic
const groupAvatarInput = document.getElementById('group-avatar-input');
if (groupAvatarInput) {
    groupAvatarInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);

        fetch(`/api/groups/${currentSettingsGroupId}/avatar`, {
            method: 'POST',
            body: formData,
            credentials: 'include'
        })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('group-avatar-preview').src = `/group/avatar/${currentSettingsGroupId}?t=${Date.now()}`;
                    loadGroups(); // Refresh list to show new avatar
                } else {
                    alert(data.error || 'Failed to upload avatar');
                }
            })
            .catch(err => alert('Upload failed'));
    });
}

const groupAvatarPreview = document.getElementById('group-avatar-preview');
if (groupAvatarPreview) {
    groupAvatarPreview.parentElement.addEventListener('click', () => {
        groupAvatarInput.click();
    });
}

// Join DM via query param
function checkDmInvite() {
    const params = new URLSearchParams(window.location.search);
    const dmWith = params.get('dm_with');
    if (dmWith) {
        // Remove param from URL
        const newUrl = window.location.pathname;
        window.history.replaceState({}, document.title, newUrl);

        // Create DM
        fetch('/api/dm/create', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ opponent_username: dmWith }),
            credentials: 'include'
        })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    window.location.href = `/group/${data.group_id}/chat`;
                } else {
                    alert(data.error || 'Failed to create DM');
                }
            });
    }
}

// Init
if (initAuth()) {
    loadGroups();
    loadSessions();
    startOnlineHeartbeat();
    checkDmInvite();
    setInterval(loadGroups, 60000);
    setInterval(loadSessions, 5000);
    setInterval(verifySessionWithServer, 30000);

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

        if (data.type === 'dm_request') {
            console.log("Received DM request:", data);
            // Update mailbox badge
            const badge = document.getElementById('mailbox-badge');
            if (badge) {
                const current = parseInt(badge.textContent || '0');
                badge.textContent = current + 1;
                badge.style.display = 'inline-block';
            }
            playNotificationSound();
        }

        if (data.type === 'dm_response') {
            console.log("Received DM response:", data);
            if (data.action === 'accept') {
                loadGroups(); // New DM group should appear
                // Show notification
                // If we had a toast system we would use it, for now just sound
                playNotificationSound();
            }
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

// ========== GROUP SETTINGS LOGIC ==========
const settingsModal = document.getElementById('group-settings-modal');
const closeSettingsBtn = document.getElementById('close-settings');
const cancelSettingsBtn = document.getElementById('btn-cancel-settings');
const saveSettingsBtn = document.getElementById('btn-save-settings');
const settingsWarning = document.getElementById('settings-warning');
let currentSettingsGroupId = null;
let currentSettingsGroupType = null;

function openSettingsModal(groupId, type) {
    currentSettingsGroupId = groupId;
    currentSettingsGroupType = type;

    const radio = document.querySelector(`input[name="settings-type"][value="${type}"]`);
    if (radio) radio.checked = true;

    settingsWarning.style.display = 'none'; // Reset warning
    settingsModal.classList.add('active');

    // Load group avatar in settings
    const avatarPreview = document.getElementById('group-avatar-preview');
    if (avatarPreview) {
        avatarPreview.src = `/group/avatar/${groupId}?t=${Date.now()}`;
    }
}

if (settingsModal) {
    const closeSettings = () => {
        settingsModal.classList.remove('active');
        currentSettingsGroupId = null;
    };

    closeSettingsBtn.addEventListener('click', closeSettings);
    cancelSettingsBtn.addEventListener('click', closeSettings);

    document.querySelectorAll('input[name="settings-type"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            if (e.target.value === 'private' && currentSettingsGroupType === 'public') {
                settingsWarning.style.display = 'block';
            } else {
                settingsWarning.style.display = 'none';
            }
        });
    });

    saveSettingsBtn.addEventListener('click', () => {
        const newType = document.querySelector('input[name="settings-type"]:checked').value;
        if (newType === currentSettingsGroupType) {
            closeSettings();
            return;
        }

        const originalText = saveSettingsBtn.textContent;
        saveSettingsBtn.textContent = 'Saving...';
        saveSettingsBtn.disabled = true;

        fetch(`/api/groups/${currentSettingsGroupId}/update_type`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ group_type: newType }),
            credentials: 'include'
        })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    // Refresh groups list
                    loadGroups();
                    closeSettings();
                } else {
                    alert(data.error || 'Failed to update settings');
                }
            })
            .catch(err => {
                console.error(err);
                alert('Failed to update settings');
            })
            .finally(() => {
                saveSettingsBtn.textContent = originalText;
                saveSettingsBtn.disabled = false;
            });
    });

    // Delete Button Logic in Settings Modal
    const btnSettingsDelete = document.getElementById('btn-settings-delete');
    if (btnSettingsDelete) {
        btnSettingsDelete.addEventListener('click', () => {
            if (currentSettingsGroupId) {
                currentDeleteGroupId = currentSettingsGroupId;
                // Close settings modal
                settingsModal.classList.remove('active');
                currentSettingsGroupId = null;

                deleteModal.classList.add('active'); // Open delete modal
            }
        });
    }
}

// ========== MAILBOX & DM LOGIC ==========
const mailboxModal = document.getElementById('mailbox-modal');
const findUserModal = document.getElementById('find-user-modal');
const mailboxList = document.getElementById('mailbox-list');
const userSearchInput = document.getElementById('user-search-input');
const userSearchResults = document.getElementById('user-search-results');

if (document.getElementById('menu-mailbox')) {
    document.getElementById('menu-mailbox').addEventListener('click', () => {
        mailboxModal.classList.add('active');
        userMenuDropdown.classList.remove('active');
        loadMailbox();
    });
}

if (document.getElementById('close-mailbox')) {
    document.getElementById('close-mailbox').addEventListener('click', () => {
        mailboxModal.classList.remove('active');
    });
}

if (document.getElementById('btn-find-users')) {
    document.getElementById('btn-find-users').addEventListener('click', () => {
        mailboxModal.classList.remove('active');
        findUserModal.classList.add('active');
        userSearchInput.value = '';
        userSearchResults.innerHTML = '';
        userSearchInput.focus();
    });
}

if (document.getElementById('close-find-user')) {
    document.getElementById('close-find-user').addEventListener('click', () => {
        findUserModal.classList.remove('active');
    });
}

function loadMailbox() {
    mailboxList.innerHTML = '<div style="text-align: center; color: #666; padding: 20px;">Loading...</div>';

    fetch('/api/dm/requests', { credentials: 'include' })
        .then(r => r.json())
        .then(data => {
            if (data.requests && data.requests.length > 0) {
                let html = '';
                data.requests.forEach(req => {
                    html += `
                    <div class="mailbox-item" style="display: flex; align-items: center; justify-content: space-between; padding: 10px; border-bottom: 1px solid #333;">
                        <div>
                            <div style="font-weight: bold;">${escapeHtml(req.sender)}</div>
                            <div style="font-size: 11px; color: #888;">${new Date(req.created_at).toLocaleString()}</div>
                        </div>
                        <div>
                            <button class="btn btn-primary btn-accept-dm" data-id="${req.id}" style="font-size: 11px; padding: 4px 8px; margin-right: 5px;">Accept</button>
                            <button class="btn btn-danger btn-decline-dm" data-id="${req.id}" style="font-size: 11px; padding: 4px 8px;">Decline</button>
                        </div>
                    </div>`;
                });
                mailboxList.innerHTML = html;

                // Add listeners
                document.querySelectorAll('.btn-accept-dm').forEach(btn => {
                    btn.addEventListener('click', () => respondToDM(btn.getAttribute('data-id'), 'accept'));
                });
                document.querySelectorAll('.btn-decline-dm').forEach(btn => {
                    btn.addEventListener('click', () => respondToDM(btn.getAttribute('data-id'), 'decline'));
                });
            } else {
                mailboxList.innerHTML = '<div style="text-align: center; color: #666; padding: 20px;">No pending requests</div>';
            }

            // Update badge
            const badge = document.getElementById('mailbox-badge');
            if (badge) {
                if (data.requests && data.requests.length > 0) {
                    badge.textContent = data.requests.length;
                    badge.style.display = 'inline-block';
                } else {
                    badge.style.display = 'none';
                }
            }
        })
        .catch(err => {
            console.error(err);
            mailboxList.innerHTML = '<div class="error">Failed to load requests</div>';
        });
}

function respondToDM(requestId, action) {
    fetch('/api/dm/respond', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ request_id: requestId, action: action }),
        credentials: 'include'
    })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                loadMailbox(); // Reload list
                if (action === 'accept') {
                    loadGroups(); // Reload groups to show new DM
                }
            } else {
                alert(data.error || 'Failed');
            }
        })
        .catch(err => alert('Network error'));
}

// User Search Logic
let searchTimeout = null;
if (userSearchInput) {
    userSearchInput.addEventListener('input', () => {
        clearTimeout(searchTimeout);
        const query = userSearchInput.value.trim();

        if (query.length < 3) {
            userSearchResults.innerHTML = '<div style="padding: 10px; color: #666;">Type at least 3 characters...</div>';
            return;
        }

        searchTimeout = setTimeout(() => {
            userSearchResults.innerHTML = '<div style="padding: 10px; color: #666;">Searching...</div>';
            fetch(`/api/users/search?q=${encodeURIComponent(query)}`, { credentials: 'include' })
                .then(r => r.json())
                .then(data => {
                    if (data.users && data.users.length > 0) {
                        let html = '';
                        data.users.forEach(u => {
                            html += `
                            <div style="display: flex; align-items: center; justify-content: space-between; padding: 10px; border-bottom: 1px solid #333;">
                                <div style="display: flex; align-items: center;">
                                    <img src="/user/profile-pic/${u.username}" alt="Avatar" style="width: 32px; height: 32px; border-radius: 50%; margin-right: 10px; object-fit: cover;" onerror="this.style.display='none'">
                                    <span>${escapeHtml(u.username)}</span>
                                </div>
                                <button class="btn btn-primary btn-send-dm" data-username="${escapeHtml(u.username)}" style="font-size: 11px; padding: 4px 8px;">Send Request</button>
                            </div>`;
                        });
                        userSearchResults.innerHTML = html;

                        document.querySelectorAll('.btn-send-dm').forEach(btn => {
                            btn.addEventListener('click', () => {
                                const username = btn.getAttribute('data-username');
                                sendDMRequest(username, btn);
                            });
                        });
                    } else {
                        userSearchResults.innerHTML = '<div style="padding: 10px; color: #666;">No users found (or they don\'t allow DMs)</div>';
                    }
                })
                .catch(err => {
                    userSearchResults.innerHTML = '<div class="error">Search failed</div>';
                });
        }, 500);
    });
}

function sendDMRequest(username, btnElement) {
    const originalText = btnElement.textContent;
    btnElement.textContent = 'Sending...';
    btnElement.disabled = true;

    fetch('/api/dm/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username }),
        credentials: 'include'
    })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                btnElement.textContent = 'Sent!';
                btnElement.classList.remove('btn-primary');
                btnElement.classList.add('btn-secondary');
            } else {
                btnElement.textContent = originalText;
                btnElement.disabled = false;
                alert(data.error || 'Failed to send request');
            }
        })
        .catch(err => {
            btnElement.textContent = originalText;
            btnElement.disabled = false;
            alert('Network error');
        });
}

// ========== PROFILE SETTINGS UPDATE ==========
document.getElementById('menu-profile-settings').addEventListener('click', () => {
    // Load current user settings
    fetch('/api/user/settings', {
        credentials: 'include'
    })
        .then(r => r.json())
        .then(data => {
            const checkbox = document.getElementById('profile-allow-dms');
            if (checkbox && data.allow_dms !== undefined) {
                checkbox.checked = data.allow_dms;
            }
        })
        .catch(err => console.error('Failed to load user settings:', err));
});

document.getElementById('profile-allow-dms').addEventListener('change', (e) => {
    const allowed = e.target.checked;
    fetch('/api/user/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ allow_dms: allowed }),
        credentials: 'include'
    }).catch(err => console.error(err));
});

// ========== GROUP SETTINGS PASSWORD UPDATE ==========
const btnChangePassword = document.getElementById('btn-change-password');
if (btnChangePassword) {
    btnChangePassword.addEventListener('click', () => {
        const rootPass = document.getElementById('settings-root-password').value;
        const newPass = document.getElementById('settings-new-password').value;
        const msgDiv = document.getElementById('password-change-msg');

        msgDiv.textContent = '';
        msgDiv.className = '';

        if (!rootPass || !newPass) {
            msgDiv.textContent = 'Both passwords required';
            msgDiv.className = 'error';
            return;
        }

        btnChangePassword.disabled = true;
        btnChangePassword.textContent = 'Updating...';

        fetch(`/api/groups/${currentSettingsGroupId}/update_password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ root_password: rootPass, new_password: newPass }),
            credentials: 'include'
        })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    msgDiv.textContent = 'Password updated successfully';
                    msgDiv.className = 'success';
                    document.getElementById('settings-root-password').value = '';
                    document.getElementById('settings-new-password').value = '';
                } else {
                    msgDiv.textContent = data.error || 'Failed';
                    msgDiv.className = 'error';
                }
            })
            .catch(err => {
                msgDiv.textContent = 'Network error';
                msgDiv.className = 'error';
            })
            .finally(() => {
                btnChangePassword.disabled = false;
                btnChangePassword.textContent = 'Update Password';
            });
    });
}
