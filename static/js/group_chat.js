// ========== EMOJI LOGIC STARTS HERE ==========
const EMOJI_DATA = {
    frequent: [],
    smileys: ['😀', '😃', '😄', '😁', '😆', '😅', '🤣', '😂', '🙂', '🙃', '😉', '😊', '😇', '🥰', '😍', '🤩', '😘', '😗', '😚', '😙', '🥲', '😋', '😛', '😜', '🤪', '😌', '😔', '😑', '😐', '😶', '🤐', '😏', '😒', '🙁', '☹️', '😬', '🤥', '😌', '😔', '😪', '🤤', '😴', '😷', '🤒', '🤕', '🤮', '🤢', '🤮', '🤮', '😵', '🤯', '🤠', '🥳', '😎', '🤓', '🧐', '😕', '😟', '🙁', '☹️', '😮', '😯', '😲', '😳', '🥺', '😦', '😧', '😨', '😰', '😥', '😢', '😭', '😱', '😖', '😣', '😞', '😓', '😩', '😫', '🥱', '😤', '😡', '😠', '🤬', '😈', '👿', '💀', '☠️', '💩', '🤡', '👹', '👺', '👻', '👽', '👾', '🤖', '😺', '😸', '😹', '😻', '😼', '😽', '🙀', '😿', '😾'],
    people: ['👋', '🤚', '🖐️', '✋', '🖖', '👌', '🤌', '🤏', '✌️', '🤞', '🫰', '🤟', '🤘', '🤙', '👍', '👎', '☝️', '👆', '👇', '☞', '👈', '👉', '🫵', '👊', '✊', '👊', '🤛', '🤜', '👏', '🙌', '👐', '🫶', '🤲', '🤝', '🤜', '🤛', '🦾', '🦿', '👂', '👃', '🧠', '🦷', '🦴', '👀', '👁️', '👅', '👄', '🐶', '🐱', '🐭', '🐹', '🐰', '🦊', '🦝', '🐻', '🐼', '🐨', '🐯', '🦁', '🐮', '🐷', '🐸', '🐵', '🙈', '🙉', '🙊', '🐒', '🐔', '🐧', '🐦', '🐤', '🦆', '🦅', '🦉', '🦇', '🐺', '🐗', '🐴', '🦄', '🐝', '🪱', '🐛', '🦋', '🐌', '🐞', '🐜', '🪰', '🐢', '🐍', '🐙', '🦐', '🦑', '🦐', '🐡', '🐠', '🐟', '🐬', '🐳', '🐋', '🦈', '🐊', '🐅', '🐆', '🦓', '🦍', '🦧', '🐘', '🦛', '🦏', '🐪', '🐫', '🦒', '🦘', '🐃', '🐂', '🐄', '🐎', '🐖', '🐏', '🐑', '🦙', '🐐', '🦌', '🐕', '🐩', '🦮', '🐈', '🐓', '🦃', '🦚', '🦜', '🦢', '🦗', '🥚', '🍳', '🍞', '🍌', '🍎', '🍊', '🍋', '🍌', '🍉', '🍇', '🍓', '🫐', '🍈', '🍒', '🍑', '🥭', '🍍', '🥥', '🥝', '🍅', '🍆', '🥑', '🥦', '🥬', '🥒', '🌶️', '🌽', '🥕', '🧄', '🧅', '🥔', '🍠', '🥐', '🥯', '🍞', '🥖', '🥨', '🧀', '🥚', '🍳', '🧈', '🥞', '🥓', '🥔', '🍟', '🍕', '🌭', '🥪', '🌮', '🌯', '🥙', '🧆', '🍔', '🍟', '🍗', '🥩', '🍖', '🌭', '🍝', '🍜', '🍲', '🍛', '🍣', '🍱', '🥟', '🦪', '🍤', '🍙', '🍚', '🍘', '🍥', '🥠', '🥮', '🍢', '🍡', '🍧', '🍨', '🍦', '🍰', '🎂', '🍮', '🍭', '🍬', '🍫', '🍿', '🍩', '🍪', '🌰', '🍯', '🥛', '🥤', '☕', '🍵', '🍶', '🍾', '🍷', '🍸', '🍹', '🍺', '🍻', '🥂', '🥃'],
    nature: ['🌿', '🀀', '☘️', '🎄', '🎄', '🌲', '🌳', '🌴', '🌱', '🌾', '💐', '🌷', '🌹', '🥀', '🌺', '🌻', '🌞', '🌝', '🌛', '🌜', '🌚', '🌕', '🌖', '🌗', '🌘', '🌑', '🌒', '🌓', '🌔', '⭐', '🌟', '✨', '⚡', '☄️', '💥', '🔥', '🌪️', '🌈', '☀️', '🌤️', '⛅', '🌥️', '☁️', '🌦️', '🌧️', '⛈️', '🌩️', '🌨️', '❄️', '☃️', '⛄', '🌬️', '💨', '💧', '💦', '☔'],
    food: ['🍏', '🎄', '🍎', '🍐', '🍊', '🍋', '🍌', '🍉', '🍇', '🍓', '🫐', '🍈', '🍒', '🍑', '🥭', '🍍', '🥥', '🥝', '🍅', '🍆', '🥑', '🥦', '🥬', '🥒', '🌶️', '🌽', '🥕', '🧄', '🧅', '🥔', '🍠', '🥐', '🥯', '🍞', '🥖', '🥨', '🧀', '🥚', '🍳', '🧈', '🥞', '🥓', '🥔', '🍟', '🍕', '🌭', '🥪', '🌮', '🌯', '🥙', '🧆', '🍔', '🍟', '🍗', '🥩', '🍖', '🌭', '🍝', '🍜', '🍲', '🍛', '🍣', '🍱', '🥟', '🦪', '🍤', '🍙', '🍚', '🍘', '🍥', '🥠', '🥮', '🍢', '🍡', '🍧', '🍨', '🍦', '🍰', '🎂', '🍮', '🍭', '🍬', '🍫', '🍿', '🍩', '🍪', '🌰', '🍯', '🥛', '🥤', '☕', '🍵', '🍶', '🍾', '🍷', '🍸', '🍹', '🍺', '🍻', '🥂', '🥃'],
    travel: ['✈️', '🛫', '🛬', '🛩️', '💺', '🛰️', '🚁', '🛶', '⛵', '🚤', '🛳️', '⛴️', '🛥️', '🛩️', '✈️', '🚀', '🛸', '🚂', '🚃', '🚄', '🚅', '🚆', '🚇', '🚈', '🚉', '🚊', '🚝', '🚞', '🚋', '🚌', '🚍', '🚎', '🚐', '🚑', '🚒', '🚓', '🚔', '🚕', '🚖', '🚗', '🚘', '🚙', '🚚', '🚛', '🚜', '🏎️', '🏍️', '🛵', '🦯', '🦽', '🦼', '🛺', '🚲', '🛴', '🛹', '🛼', '🚏', '⛽', '🚨', '🚥', '🚦', '🛑', '🚧', '⚓', '⛵', '🚤', '🛳️', '🛥️', '🚢', '✈️', '🛫', '🛬', '🛩️', '💺', '🛰️', '🚁', '🛶', '⛵', '🚤', '🛳️', '🛥️', '🛢️', '⛽', '🚨', '🚥', '🚦', '🛑', '⚓', '⛵', '🚤', '🛳️', '🛥️', '🏝️', '⛱️', '🏖️', '🏜️', '🌋', '⛰️', '🏔️', '🗻', '🏕️', '⛺', '⛲', '🏞️', '🛣️', '🛤️', '🗾', '🎡', '🎢', '🎠', '⛲', '⛺', '🏕️', '🗼', '🗽', '🗿', '🎪', '🎭', '🎨'],
    objects: ['⚽', '⚾', '🥎', '🎾', '🏀', '🏐', '🏈', '🏉', '🎱', '🎳', '🏓', '🏸', '🥊', '🥋', '🎣', '🎽', '🎿', '⛷️', '🛷', '🥌', '🎯', '🪀', '🪁', '🎨', '🎬', '🎤', '🎧', '🎼', '🎹', '🥁', '🎷', '🎺', '🎸', '🪗', '🎻', '🎲', '♟️', '🎯', '🎳', '🎮', '🎰', '🧩', '🚗', '🚕', '🚙', '🚌', '🚎', '🏎️', '🚓', '🚑', '🚒', '🚐', '🛻', '🚚', '🚛', '🚜', '🏍️', '🏎️', '🛵', '🦯', '🦽', '🦼', '🛺', '🚲', '🛴', '🛹', '🛼', '🛞', '🚨', '🚔', '🚍', '🚘', '🚖', '🚡', '🚠', '🚟', '🚃', '🚋', '🚞', '🚝', '🚄', '🚅', '🚈', '2', '🚆', '🚇', '🚊', '🚉', '🚌', '🚎', '🚐', '🛒', '🚚', '🚛', '✈️', '🛫', '🛬', '🛩️', '💺', '🛰️'],
    symbols: ['❤️', '🧡', '💛', '💚', '💙', '💜', '🖤', '🤍', '🤎', '💔', '💕', '💞', '💓', '💗', '💖', '💘', '💝', '💟', '💌', '💜', '💛', '💚', '💙', '💜', '❤️', '🧡', '💛', '💚', '💙', '💜', '🖤', '🤍', '🤎', '💔', '✅', '❌', '⎈', '✔️', '❌', '➕', '➖', '➗', '➘', '➙', '➚', '➛', '➜', '➝', '➞', '➟', '➠', '➡️', '➢', '➣', '➤', '➥', '➦', '➧', '➨', '➩', '➪', '➫', '➬', '➭', '➮', '➯', '🔚', '🔙', '🔛', '🔜', '🔝', '🔴', '🟠', '🟡', '🟢', '🔵', '🟣', '⚫', '⚪', '🟤', '🟥', '🟧', '🟨', '🟩', '🟦', '🟪', '⬛', '⬜', '🟫', '🟰']
};

let recentEmojis = [];

function saveRecentEmoji(emoji) {
    recentEmojis = [emoji, ...recentEmojis.filter(e => e !== emoji)].slice(0, 10);
}

function loadRecentEmojis() {
    EMOJI_DATA.frequent = recentEmojis.length > 0 ? recentEmojis : ['😊', '😂', '❤️', '👍', '🔥', '👏', '✨', '💯'];
}

loadRecentEmojis();

const emojiBtn = document.getElementById('emoji-btn');
const emojiModal = document.getElementById('emoji-picker-modal');
const emojiCloseBtn = document.getElementById('emoji-close-btn');
const emojiSearch = document.getElementById('emoji-search');
const emojiGrid = document.getElementById('emoji-grid');
const emojiTabs = document.querySelectorAll('.emoji-tab');

let currentCategory = 'frequent';

emojiBtn.addEventListener('click', () => {
    emojiModal.classList.add('active');
    renderEmojiGrid('frequent');
    emojiSearch.focus();
});

emojiCloseBtn.addEventListener('click', () => {
    emojiModal.classList.remove('active');
    emojiSearch.value = '';
});

document.addEventListener('click', (e) => {
    if (!emojiModal.contains(e.target) && e.target !== emojiBtn) {
        emojiModal.classList.remove('active');
    }
});

emojiTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        emojiTabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        currentCategory = tab.dataset.category;
        emojiSearch.value = '';
        renderEmojiGrid(currentCategory);
    });
});

emojiSearch.addEventListener('input', () => {
    const query = emojiSearch.value.toLowerCase();
    if (!query) {
        renderEmojiGrid(currentCategory);
        return;
    }
    emojiTabs.forEach(t => t.classList.remove('active'));
    renderSearchResults(query);
});

function renderEmojiGrid(category) {
    const emojis = EMOJI_DATA[category] || [];
    emojiGrid.innerHTML = '';

    if (emojis.length === 0) {
        emojiGrid.innerHTML = '<div class="emoji-no-results">No emojis</div>';
        return;
    }

    emojis.forEach(emoji => {
        const item = document.createElement('div');
        item.className = 'emoji-item';
        item.textContent = emoji;
        item.addEventListener('click', () => {
            insertEmoji(emoji);
            saveRecentEmoji(emoji);
            loadRecentEmojis();
        });
        emojiGrid.appendChild(item);
    });
}

function renderSearchResults(query) {
    emojiGrid.innerHTML = '';
    const results = [];

    Object.values(EMOJI_DATA).forEach(emojis => {
        emojis.forEach(emoji => {
            if (!results.includes(emoji)) {
                results.push(emoji);
            }
        });
    });

    const filtered = results.slice(0, 100);

    if (filtered.length === 0) {
        emojiGrid.innerHTML = '<div class="emoji-no-results">No results</div>';
        return;
    }

    filtered.forEach(emoji => {
        const item = document.createElement('div');
        item.className = 'emoji-item';
        item.textContent = emoji;
        item.addEventListener('click', () => {
            insertEmoji(emoji);
            saveRecentEmoji(emoji);
            loadRecentEmojis();
        });
        emojiGrid.appendChild(item);
    });
}

function insertEmoji(emoji) {
    const input = document.getElementById('in');
    const start = input.selectionStart;
    const end = input.selectionEnd;
    const text = input.value;

    input.value = text.substring(0, start) + emoji + text.substring(end);
    input.selectionStart = input.selectionEnd = start + emoji.length;
    input.focus();

    emojiModal.classList.remove('active');
}

renderEmojiGrid('frequent');
// ========== EMOJI LOGIC ENDS HERE ==========

// ========== CORE CHAT VARIABLES ==========
let AUTH_TOKEN = null;
let CURRENT_USER = null;
let GROUP_SESSION_TOKEN = null;
let MEMBERS_UPDATE_INTERVAL = null;
let ONLINE_HEARTBEAT_INTERVAL = null;
let isUnloading = false;
let selectedFile = null;
let isUploadingFile = false;
let messageIdToElementMap = new Map();
let pendingDeleteMessageId = null;
let memberProfilePics = new Map(); // Stores username -> has_profile_pic (bool)

console.log('[Init] Group chat page loaded. Group ID:', GROUP_ID);

function showError(message, duration = 5000) {
    const notification = document.getElementById('error-notification');
    notification.textContent = message;
    notification.classList.add('active');
    notification.classList.add('error');
    notification.classList.remove('success');
    setTimeout(() => {
        notification.classList.remove('active');
    }, duration);
}

function showSuccess(message, duration = 3000) {
    const notification = document.getElementById('error-notification');
    notification.textContent = message;
    notification.classList.add('active');
    notification.classList.add('success');
    notification.classList.remove('error');

    setTimeout(() => {
        notification.classList.remove('active');
    }, duration);
}

// ========== MODAL FUNCTIONS ==========
function showDeleteConfirmModal(messageId) {
    pendingDeleteMessageId = messageId;
    const modal = document.getElementById('confirm-modal');
    modal.classList.add('active');
}

function hideDeleteConfirmModal() {
    const modal = document.getElementById('confirm-modal');
    modal.classList.remove('active');
    pendingDeleteMessageId = null;
}

document.getElementById('modal-cancel').addEventListener('click', hideDeleteConfirmModal);
document.getElementById('modal-confirm').addEventListener('click', function () {
    if (pendingDeleteMessageId !== null) {
        executeDeleteMessage(pendingDeleteMessageId);
    }
    hideDeleteConfirmModal();
});
document.getElementById('confirm-modal').addEventListener('click', function (e) {
    if (e.target === this) {
        hideDeleteConfirmModal();
    }
});
document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
        hideDeleteConfirmModal();
    }
});

// ========== AUTHENTICATION ==========
function initAuth() {
    console.log('[Init] Initializing authentication...');
    CURRENT_USER = localStorage.getItem('username');
    console.log('[Auth] Current user:', CURRENT_USER);
    console.log('[Auth] Template user:', TEMPLATE_USER);

    if (!CURRENT_USER) {
        console.error('[Auth] No username in localStorage - redirecting to login');
        alert('Session lost. Please login again.');
        window.location.href = '/login';
        return false;
    }

    if (TEMPLATE_USER && TEMPLATE_USER !== CURRENT_USER) {
        console.error('[Auth] User mismatch! Template:', TEMPLATE_USER, 'Local:', CURRENT_USER);
        alert('SECURITY ERROR: User verification failed. Logging you out.');
        localStorage.removeItem('username');
        window.location.href = '/login';
        return false;
    }

    if (TEMPLATE_GROUP_TOKEN) {
        GROUP_SESSION_TOKEN = TEMPLATE_GROUP_TOKEN;
        console.log('[Auth] Using group session token from template');
    } else {
        console.error('[Auth] No group session token from server');
        alert('Session lost. Please login again.');
        window.location.href = '/login';
        return false;
    }

    setupChat();
    return true;
}

function setupChat() {
    console.log('[Chat] Setting up chat interface...');
    document.getElementById('chat-user').textContent = CURRENT_USER;
    document.getElementById('group-name').textContent = GROUP_NAME;
    // Load members first with callback to load history after
    loadMembers(() => {
        console.log('[Chat] Members loaded, now loading history...');
        loadHistory();
    });
    MEMBERS_UPDATE_INTERVAL = setInterval(loadMembers, 10000);
    sendOnlineHeartbeat();
    ONLINE_HEARTBEAT_INTERVAL = setInterval(sendOnlineHeartbeat, 20000);

    // Load groups sidebar
    loadGroups();
    setInterval(loadGroups, 60000);

    // Back button
    const btnBack = document.getElementById('btn-back-groups');
    if (btnBack) {
        btnBack.addEventListener('click', () => {
            window.location.href = '/groups';
        });
    }
}

// ========== GROUPS SIDEBAR ==========
let currentDeleteGroupId = null;
const deleteModal = document.getElementById('delete-modal');

function loadGroups() {
    fetch('/api/groups/list?t=' + Date.now(), { credentials: 'include' })
        .then(r => {
            if (r.status === 401) {
                handleSessionExpired();
                return null;
            }
            return r.json();
        })
        .then(data => { if (data) renderGroups(data.groups); })
        .catch(err => console.warn('[Groups] Failed to load groups:', err));
}

function renderGroups(groups) {
    const list = document.getElementById('groups-list');
    if (!list) return;

    if (!groups || groups.length === 0) {
        list.innerHTML = '<div class="members-empty">No groups</div>';
        return;
    }

    // Sort by last message
    groups.sort((a, b) => b.last_message_at - a.last_message_at);

    let html = '';
    groups.forEach(group => {
        const isActive = group.id === GROUP_ID;
        const activeClass = isActive ? ' active' : '';
        const isCreator = group.role === 'creator';

        let badgeHtml = '';
        if (group.unread_count > 0 && !isActive) {
            const countText = group.unread_count > 99 ? '99+' : group.unread_count;
            badgeHtml = `<span class="unread-badge">${countText}</span>`;
        }

        const deleteBtnHtml = isCreator ? `<button class="btn-delete-group" data-group-id="${group.id}">Delete</button>` : '';

        html += `<div class="group-item${activeClass}" data-group-id="${group.id}">
          <div class="group-name">
              <span>${escapeHtml(group.name)}</span>
              <div style="display:flex; align-items:center;">
                  ${badgeHtml}
                  ${deleteBtnHtml}
              </div>
          </div>
          <div class="group-code">#${group.code}</div>
        </div>`;
    });
    list.innerHTML = html;

    // Add event listeners (replacing inline onclick)
    document.querySelectorAll('.group-item').forEach(item => {
        item.addEventListener('click', (e) => {
            // Don't trigger if delete button was clicked
            if (e.target.classList.contains('btn-delete-group')) return;

            const groupId = item.getAttribute('data-group-id');
            window.location.href = '/group/' + groupId + '/chat';
        });
    });

    document.querySelectorAll('.btn-delete-group').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            currentDeleteGroupId = btn.getAttribute('data-group-id');
            deleteModal.classList.add('active');
        });
    });
}

// Delete Modal Logic
if (deleteModal) {
    document.getElementById('btn-cancel-delete').addEventListener('click', () => {
        deleteModal.classList.remove('active');
        document.getElementById('delete-password').value = '';
        document.getElementById('delete-error').innerHTML = '';
    });

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
                    // If we deleted the current group, go back to groups list
                    if (currentDeleteGroupId == GROUP_ID) {
                        window.location.href = '/groups';
                    } else {
                        loadGroups();
                        setTimeout(() => {
                            deleteModal.classList.remove('active');
                            document.getElementById('delete-password').value = '';
                            errorDiv.innerHTML = '';
                        }, 1000);
                    }
                } else {
                    errorDiv.innerHTML = '<div class="error">' + d.error + '</div>';
                }
            })
            .catch(err => {
                errorDiv.innerHTML = '<div class="error">Failed to delete</div>';
            });
    });
}

function handleSessionExpired() {
    console.error('[Auth] Session expired');
    isUnloading = true;
    clearInterval(MEMBERS_UPDATE_INTERVAL);
    clearInterval(ONLINE_HEARTBEAT_INTERVAL);
    showError('✗ Your session has expired. Redirecting...');
    setTimeout(() => {
        localStorage.removeItem('username');
        window.location.href = '/login';
    }, 1500);
}

function getCurrentUser() {
    const stored = localStorage.getItem('username');
    if (!stored || stored !== CURRENT_USER) {
        console.error('[Auth] User mismatch in getCurrentUser()');
        handleSessionExpired();
        return null;
    }
    return CURRENT_USER;
}

// ========== MEMBERS MANAGEMENT ==========
function loadMembers(callback) {
    const user = getCurrentUser();
    if (!user) return;

    fetch(`/api/groups/${GROUP_ID}/members`, {
        headers: { 'Authorization': `Bearer ${GROUP_SESSION_TOKEN}` },
        credentials: 'include'
    })
        .then(response => {
            if (response.status === 401) {
                console.error('[Members] 401 - Session expired');
                handleSessionExpired();
                return null;
            }
            return response.json();
        })
        .then(data => {
            if (!data) return;
            renderMembers(data.members, data.total);
            // Call callback after members are rendered and memberProfilePics Map is populated
            if (callback && typeof callback === 'function') {
                callback();
            }
        })
        .catch(err => console.error('[Members] Failed:', err));
}

function renderMembers(members, total) {
    const membersList = document.getElementById('members-list');
    const membersCount = document.getElementById('members-count');
    membersCount.textContent = `(${total})`;

    if (!members || members.length === 0) {
        membersList.innerHTML = '<div class="members-empty">No members</div>';
        return;
    }

    let html = '';
    members.forEach(member => {
        const isOnline = member.is_online;
        const isCreator = member.role === 'creator';
        const isCurrentUser = member.username === CURRENT_USER;

        let className = 'member-item ';
        if (isCreator) className += 'creator ';
        className += isOnline ? 'online' : 'offline';

        const dot = isOnline
            ? '<span class="member-online-dot"></span>'
            : '<span class="member-offline-dot"></span>';

        const roleLabel = isCreator ? '<span class="member-role">👑</span>' : '';
        const userLabel = isCurrentUser ? ' <span class="member-role">(you)</span>' : '';

        // Avatar for member
        const avatarSrc = member.has_profile_pic
            ? `/user/profile-pic/${member.username}`
            : '/static/unknown_user_phasma_icon.png';

        html += `
          <div class="${className}">
            <img src="${avatarSrc}" alt="${escapeHtml(member.username)}" class="member-avatar">
            ${dot}<span class="member-username">${escapeHtml(member.username)}</span>${userLabel}${roleLabel}
          </div>
        `;

        // Update profile pic cache
        memberProfilePics.set(member.username, member.has_profile_pic);
    });
    membersList.innerHTML = html;
}

function sendOnlineHeartbeat() {
    const user = getCurrentUser();
    if (!user) return;

    fetch(`/api/groups/${GROUP_ID}/members/online`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${GROUP_SESSION_TOKEN}` },
        credentials: 'include'
    }).catch(err => console.warn('[Online] Failed:', err));
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ========== TIME FORMATTING ==========
function formatLocalTime(timestamp) {
    try {
        const ts = typeof timestamp === 'string' ?
            parseInt(timestamp, 10) : timestamp;
        const date = new Date(ts * 1000);
        if (isNaN(date.getTime())) return "??:??:??";
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        const seconds = String(date.getSeconds()).padStart(2, '0');
        return `${hours}:${minutes}:${seconds}`;
    } catch (e) {
        return "??:??:??";
    }
}

function formatLocalDate() {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
}

function formatDateFromTimestamp(timestamp) {
    try {
        const ts = typeof timestamp === 'string' ?
            parseInt(timestamp, 10) : timestamp;
        const date = new Date(ts * 1000);
        if (isNaN(date.getTime())) return formatLocalDate();
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    } catch (e) {
        return formatLocalDate();
    }
}

// ========== DELETE MESSAGE ==========
function executeDeleteMessage(messageId) {
    const user = getCurrentUser();
    if (!user) return;

    $.ajax({
        url: `/group/${GROUP_ID}/message/${messageId}/delete`,
        type: 'POST',
        headers: { 'Authorization': `Bearer ${GROUP_SESSION_TOKEN}` },
        success: function () {
            console.log('[Delete] Message deleted:', messageId);

            const msgElement = messageIdToElementMap.get(messageId);
            if (msgElement) {
                msgElement.classList.add('message-deleted');
                msgElement.innerHTML = '<div class="message-header">[deleted]</div>';
                messageIdToElementMap.delete(messageId);
            }

            showSuccess('✓ Message deleted');
        },
        error: function (xhr) {
            console.error('[Delete] Failed:', xhr.status);

            if (xhr.status === 401) {
                handleSessionExpired();
                return;
            }

            if (xhr.status === 403) {
                showError('✗ You can only delete your own messages');
                return;
            }

            try {
                const response = JSON.parse(xhr.responseText);
                showError(`✗ Delete failed: ${response.error}`);
            } catch (e) {
                showError('✗ Failed to delete message');
            }
        }
    });
}

// ========== MESSAGE PARSING & RENDERING ==========
function parseMessageData(data) {
    const timeMatch = data.match(/^\[(\d+)\]\s+/);
    if (!timeMatch) return null;
    const timestamp = parseInt(timeMatch[1], 10);
    const afterTime = data.substring(timeMatch[0].length);

    const userMatch = afterTime.match(/^([^:]+):\s*/);
    if (!userMatch) return null;

    const username = userMatch[1];
    const rest = afterTime.substring(userMatch[0].length);

    const urlsSplit = rest.split('|URLS:');
    const content = urlsSplit[0];
    let urls = {};

    if (urlsSplit.length > 1) {
        try {
            urls = JSON.parse(urlsSplit[1]);
        } catch (e) {
            urls = {};
        }
    }

    return { timestamp, username, content, urls };
}

function createURLPreviewCard(url, preview) {
    const card = document.createElement("div");
    card.className = "url-preview-card";
    const serviceDiv = document.createElement("div");
    serviceDiv.className = "url-preview-service";
    serviceDiv.textContent = preview.service_type || 'LINK';
    card.appendChild(serviceDiv);

    const urlDiv = document.createElement("div");
    urlDiv.className = "url-preview-url";
    urlDiv.style.cursor = 'pointer';
    urlDiv.textContent = url.substring(0, 60) + (url.length > 60 ? '...' : '');
    card.appendChild(urlDiv);
    if (preview.title) {
        const titleDiv = document.createElement("div");
        titleDiv.className = "url-preview-title";
        titleDiv.textContent = preview.title;
        card.appendChild(titleDiv);
    }

    if (preview.description) {
        const descDiv = document.createElement("div");
        descDiv.className = "url-preview-description";
        descDiv.textContent = preview.description.substring(0, 100);
        card.appendChild(descDiv);
    }

    if (preview.thumbnail_url) {
        const img = document.createElement("img");
        img.className = "url-preview-thumbnail";
        img.src = preview.thumbnail_url;
        img.alt = "Preview";
        img.loading = "lazy";
        img.onerror = () => img.style.display = 'none';
        img.onclick = (e) => { e.stopPropagation(); window.open(url, '_blank'); };
        card.appendChild(img);
    }

    card.onclick = () => window.open(url, '_blank');
    return card;
}

function createMessageElement(data, messageId) {
    const parsed = parseMessageData(data);
    if (!parsed) {
        const msg = document.createElement("div");
        msg.className = "message";
        msg.textContent = "[PARSE ERROR]";
        return msg;
    }

    const msgWrapper = document.createElement("div");
    msgWrapper.className = "message";
    msgWrapper.setAttribute('data-message-id', messageId);

    const localTime = formatLocalTime(parsed.timestamp);
    const localDate = formatDateFromTimestamp(parsed.timestamp);

    // Avatar
    const avatarImg = document.createElement("img");
    avatarImg.className = "message-avatar";
    const hasPic = memberProfilePics.get(parsed.username);
    if (hasPic) {
        avatarImg.src = `/user/profile-pic/${parsed.username}`;
    } else {
        avatarImg.src = "/static/unknown_user_phasma_icon.png";
    }
    avatarImg.alt = parsed.username;
    msgWrapper.appendChild(avatarImg);

    // Content Wrapper (Username + Message Content)
    const contentWrapper = document.createElement("div");
    contentWrapper.className = "message-content-wrapper";

    // Username and timestamp header
    const header = document.createElement("div");
    header.className = "message-header";
    header.innerHTML = `<strong>${escapeHtml(parsed.username)}</strong> <span class="message-time">${localDate}, ${localTime}</span>`;
    contentWrapper.appendChild(header);

    const mainContent = document.createElement("div");
    mainContent.className = "message-content";
    if (parsed.content.startsWith("[AUDIO:")) {
        const audioMatch = parsed.content.match(/^\[AUDIO:(\d+):(.+)\]$/);
        if (audioMatch) {
            const audioDiv = document.createElement("div");
            audioDiv.className = "audio-msg";
            const audio = document.createElement("audio");
            audio.className = "audio-player";
            audio.src = audioMatch[2];
            audio.controls = true;
            audioDiv.appendChild(audio);
            mainContent.appendChild(audioDiv);
        }
    }
    else if (parsed.content.startsWith("[VIDEO:")) {
        const videoMatch = parsed.content.match(/^\[VIDEO:(\d+):(.+)\]$/);
        if (videoMatch) {
            const videoDiv = document.createElement("div");
            videoDiv.className = "video-msg";
            const video = document.createElement("video");
            video.className = "video-player";
            video.src = videoMatch[2];
            video.controls = true;
            videoDiv.appendChild(video);
            mainContent.appendChild(videoDiv);
        }
    }
    else if (parsed.content.startsWith("[PHOTO:")) {
        const photoMatch = parsed.content.match(/^\[PHOTO:(\d+):(.+)\]$/);
        if (photoMatch) {
            const photoDiv = document.createElement("div");
            photoDiv.className = "photo-msg";
            const img = document.createElement("img");
            img.src = photoMatch[2];
            img.alt = "Photo";
            img.loading = "lazy";
            img.style.cursor = "pointer";
            img.onclick = () => window.open(photoMatch[2], '_blank');
            photoDiv.appendChild(img);
            mainContent.appendChild(photoDiv);
        }
    }
    else if (parsed.content.startsWith("[FILE:")) {
        const fileMatch = parsed.content.match(/^\[FILE:(\d+):([^:]+):(.+?):(.+)\]$/);
        if (fileMatch) {
            const fileDiv = document.createElement("div");
            fileDiv.className = "file-msg";
            const fileAttachment = document.createElement("div");
            fileAttachment.className = "file-attachment";

            const fileIcon = document.createElement("img");
            fileIcon.className = "file-icon";
            fileIcon.src = "/static/phasma_file.png";
            const fileInfo = document.createElement("div");
            fileInfo.className = "file-info";
            const fileName = document.createElement("div");
            fileName.className = "file-name";
            fileName.textContent = fileMatch[3];
            fileInfo.appendChild(fileName);
            const downloadBtn = document.createElement("button");
            downloadBtn.className = "file-download-btn";
            downloadBtn.textContent = "⬇";
            downloadBtn.onclick = () => {
                const a = document.createElement('a');
                a.href = fileMatch[4];
                a.download = fileMatch[3];
                a.click();
            };

            fileAttachment.appendChild(fileIcon);
            fileAttachment.appendChild(fileInfo);
            fileAttachment.appendChild(downloadBtn);
            fileDiv.appendChild(fileAttachment);
            mainContent.appendChild(fileDiv);
        }
    }
    else {
        const textDiv = document.createElement("div");
        textDiv.className = "message-text";
        textDiv.textContent = parsed.content;
        mainContent.appendChild(textDiv);

        if (parsed.urls && Object.keys(parsed.urls).length > 0) {
            const previewsContainer = document.createElement("div");
            previewsContainer.className = "url-previews";
            for (const [url, preview] of Object.entries(parsed.urls)) {
                previewsContainer.appendChild(createURLPreviewCard(url, preview));
            }
            mainContent.appendChild(previewsContainer);
        }
    }

    contentWrapper.appendChild(mainContent);
    msgWrapper.appendChild(contentWrapper);
    const isOwnMessage = parsed.username === CURRENT_USER;
    if (isOwnMessage) {
        const deleteBtn = document.createElement("button");
        deleteBtn.className = "message-delete-btn";
        deleteBtn.textContent = "🗑️ delete";
        deleteBtn.onclick = (e) => {
            e.stopPropagation();
            showDeleteConfirmModal(messageId);
        };

        msgWrapper.appendChild(deleteBtn);
        messageIdToElementMap.set(messageId, msgWrapper);
    }

    return msgWrapper;
}

// ========== CHAT HISTORY & STREAMING ==========
let loadedMessageIds = new Set();
let oldestMessageId = null;
let newestMessageId = null;
let isLoadingHistory = false;
let hasMoreHistory = true;
let initialLoadDone = false;
let sseStarted = false;

const out = document.getElementById("out");
const messagesContainer = document.getElementById("messages-container");
const loadMoreBtn = document.getElementById("load-more-btn");
const loadMoreContainer = document.getElementById("load-more-container");
function loadHistory() {
    if (isLoadingHistory || !hasMoreHistory) return;
    isLoadingHistory = true;
    loadMoreBtn.disabled = true;
    loadMoreBtn.textContent = "Loading...";

    const scrollContainer = out;
    const oldScrollHeight = scrollContainer.scrollHeight;
    const oldScrollTop = scrollContainer.scrollTop;
    const url = oldestMessageId
        ?
        `/group/${GROUP_ID}/history?before_id=${oldestMessageId}&limit=50`
        : `/group/${GROUP_ID}/history?limit=50`;
    fetch(url, {
        headers: { 'Authorization': `Bearer ${GROUP_SESSION_TOKEN}` },
        credentials: 'include'
    })
        .then(response => {
            if (response.status === 401) {
                handleSessionExpired();
                return null;
            }
            return response.json();
        })
        .then(data => {
            if (!data) return;
            if (data.messages.length === 0) {
                hasMoreHistory = false;
                loadMoreBtn.textContent = "No more messages";
                setTimeout(() => loadMoreContainer.style.display = "none", 2000);
                return;
            }

            const messageElements = [];
            data.messages.forEach(msg => {
                if (!loadedMessageIds.has(msg.id)) {
                    loadedMessageIds.add(msg.id);
                    const msgElement = createMessageElement(msg.text, msg.id);
                    messageElements.push({ element: msgElement, id: msg.id });

                    if (!oldestMessageId || msg.id < oldestMessageId) {
                        oldestMessageId = msg.id;
                    }
                    if (!newestMessageId || msg.id > newestMessageId) {
                        newestMessageId = msg.id;
                    }
                }
            });
            if (initialLoadDone) {
                for (let i = messageElements.length - 1; i >= 0; i--) {
                    messagesContainer.insertBefore(messageElements[i].element, messagesContainer.firstChild);
                }
            } else {
                messageElements.forEach(item => messagesContainer.appendChild(item.element));
            }

            if (initialLoadDone) {
                requestAnimationFrame(() => {
                    const newScrollHeight = scrollContainer.scrollHeight;
                    scrollContainer.scrollTop = oldScrollTop + (newScrollHeight - oldScrollHeight);
                });
            }

            hasMoreHistory = data.has_more;
            if (!hasMoreHistory) {
                loadMoreBtn.textContent = "No more messages";
                setTimeout(() => loadMoreContainer.style.display = "none", 2000);
            } else {
                loadMoreBtn.textContent = "↑ Load older messages";
            }

            if (!initialLoadDone) {
                initialLoadDone = true;
                requestAnimationFrame(() => {
                    scrollContainer.scrollTop = scrollContainer.scrollHeight;
                    if (!sseStarted) {
                        sseStarted = true;
                        startSSE();
                    }
                });
            }
        })
        .catch(err => {
            console.error("Failed to load history:", err);
            loadMoreBtn.textContent = "⚠ Error - try again";
            hasMoreHistory = true;
        })
        .finally(() => {
            isLoadingHistory = false;
            loadMoreBtn.disabled = false;
        });
}

out.addEventListener('scroll', () => {
    if (out.scrollTop < 100 && hasMoreHistory && !isLoadingHistory) {
        loadMoreContainer.style.display = "block";
    } else if (out.scrollTop > 200) {
        loadMoreContainer.style.display = "none";
    }
});
loadMoreBtn.addEventListener('click', loadHistory);

function startSSE() {
    fetch(`/group/${GROUP_ID}/stream`, {
        headers: { 'Authorization': `Bearer ${GROUP_SESSION_TOKEN}` },
        credentials: 'include'
    }).then(response => {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        function read() {
            reader.read().then(({ done, value }) => {
                if (done) return;

                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split('\n');

                buffer = lines.pop()
                    || '';

                lines.forEach(line => {
                    if (line.startsWith('data: ')) {
                        const data = line.slice(6).trim();
                        if (!data) return;

                        if (data.startsWith('DELETE_MESSAGE:')) {
                            const messageId = parseInt(data.substring(15), 10);
                            console.log('[SSE] Message deleted:', messageId);

                            const msgElement = document.querySelector(`[data-message-id="${messageId}"]`);
                            if (msgElement) {
                                msgElement.style.transition = 'all 0.3s ease-out';
                                msgElement.style.opacity = '0';
                                msgElement.style.height = '0';
                                msgElement.style.margin = '0';
                                msgElement.style.overflow = 'hidden';
                                setTimeout(() => {
                                    msgElement.remove();
                                    messageIdToElementMap.delete(messageId);
                                }, 300);
                            }
                            return;
                        }

                        const msgElement = createMessageElement(data, Date.now() + Math.random());
                        messagesContainer.appendChild(msgElement);

                        // Play notification sound if message is not from current user
                        const timeMatch = data.match(/^\[(\d+)\]\s+/);
                        if (timeMatch) {
                            const afterTime = data.substring(timeMatch[0].length);
                            const userMatch = afterTime.match(/^([^:]+):\s*/);
                            if (userMatch) {
                                const msgUsername = userMatch[1];
                                if (msgUsername !== CURRENT_USER) {
                                    const audio = new Audio('/static/phasma_notification_sound.mp3');
                                    audio.play().catch(e => console.log('Audio play failed:', e));
                                }
                            }
                        }

                        const isNearBottom = out.scrollHeight - out.scrollTop - out.clientHeight < 150;
                        if (isNearBottom) {
                            requestAnimationFrame(() => {
                                out.scrollTop = out.scrollHeight;
                            });
                        }
                    }
                });
                read();
            });
        }
        read();
    }).catch(err => console.error("[SSE] Failed:", err));
}

// ========== SENDING MESSAGES & FILES ==========
function sendMessageOrFile() {
    if (isUploadingFile) {
        showError('⏳ Upload in progress. Please wait...');
        return;
    }

    if (selectedFile) {
        sendFile();
        return;
    }

    const text = document.getElementById('in').value;
    if (!text.trim()) return;
    $.ajax({
        url: `/group/${GROUP_ID}/post`,
        type: 'POST',
        headers: { 'Authorization': `Bearer ${GROUP_SESSION_TOKEN}` },
        data: { message: text },
        success: function () {
            document.getElementById('in').value = '';
        },
        error: function (xhr) {
            if (xhr.status === 429) {
                showError('✗ You are sending requests too quickly. Try again later.');
            } else if (xhr.status === 401) {
                handleSessionExpired();
            } else if (xhr.status === 400) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    if (response.error === 'Message too long') {
                        showError(`✗ Message too long! Maximum: ${response.max_length} characters.`);
                    }
                } catch (e) {
                    showError('✗ Invalid request.');
                }
            } else {
                showError('✗ Failed to send message.');
            }
        }
    });
}

async function sendFile() {
    if (!selectedFile) return;
    if (isUploadingFile) return;
    isUploadingFile = true;

    const formData = new FormData();
    formData.append('file', selectedFile);
    $.ajax({
        url: `/group/${GROUP_ID}/upload`,
        type: 'POST',
        headers: { 'Authorization': `Bearer ${GROUP_SESSION_TOKEN}` },
        data: formData,
        processData: false,
        contentType: false,
        success: function (response) {
            console.log('[Upload] File sent successfully');
            hideFilePreview();
            isUploadingFile = false;
        },
        error: function (xhr) {
            isUploadingFile = false;
            try {
                const response = JSON.parse(xhr.responseText);
                const message = response.message || response.error || 'Unknown error';
                showError(`✗ Upload failed: ${message}`);
            } catch (e) {
                if (xhr.status === 429) {
                    showError('✗ Too many requests. Try again later.');
                } else if (xhr.status === 401) {
                    showError('✗ Session expired. Please login again.');
                    handleSessionExpired();
                } else if (xhr.status === 400) {
                    showError('✗ Invalid file. Please check the file and try again.');
                } else {
                    showError(`✗ Upload failed (${xhr.status})`);
                }
            }
        }
    });
}

document.getElementById('send-btn').addEventListener('click', sendMessageOrFile);
document.getElementById('in').addEventListener('keyup', function (e) {
    if (e.keyCode === 13 && !e.shiftKey) {
        e.preventDefault();
        sendMessageOrFile();
    }
});
// ========== FILE HANDLING ==========
const ALLOWED_EXTENSIONS = {
    'jpg': true, 'jpeg': true, 'png': true, 'gif': true, 'webp': true,
    'mp4': true, 'mov': true, 'webm': true,
    'mp3': true, 'm4a': true, 'ogg': true, 'wav': true,
    'pdf': true, 'txt': true
};
const MAX_FILE_SIZES = {
    'jpg': 10, 'jpeg': 10, 'png': 10, 'gif': 10, 'webp': 10,
    'mp4': 100, 'mov': 100, 'webm': 100,
    'mp3': 50, 'm4a': 50, 'ogg': 50, 'wav': 50,
    'pdf': 25, 'txt': 25
};
function getFileExtension(filename) {
    if (!filename || !filename.includes('.')) return '';
    return filename.split('.').pop().toLowerCase();
}

function validateFileExtension(ext) {
    return ALLOWED_EXTENSIONS[ext] === true;
}

function validateFileSize(file, ext) {
    const maxSizeMB = MAX_FILE_SIZES[ext] || 10;
    const maxSizeBytes = maxSizeMB * 1024 * 1024;
    return file.size <= maxSizeBytes;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function processFileUpload(file, source = 'upload') {
    const ext = getFileExtension(file.name);
    if (!validateFileExtension(ext)) {
        const allowedExts = Object.keys(ALLOWED_EXTENSIONS).join(', ');
        showError(`✗ File format ".${ext}" not allowed. Allowed: ${allowedExts}`);
        return;
    }

    if (!validateFileSize(file, ext)) {
        const maxSize = MAX_FILE_SIZES[ext] || 10;
        showError(`✗ File too large. Maximum size: ${maxSize}MB`);
        return;
    }

    if (file.size < 100) {
        showError('✗ File is too small (minimum 100 bytes)');
        return;
    }

    showFilePreview(file, source);
}

function showFilePreview(file, source = 'upload') {
    selectedFile = file;
    const container = document.getElementById('file-preview-container');
    const filename = document.getElementById('preview-filename');
    const filesize = document.getElementById('preview-filesize');
    const sourceLabel = document.getElementById('preview-source');
    const previewImg = document.getElementById('preview-img');
    const previewVideo = document.getElementById('preview-video');
    const previewIcon = document.getElementById('preview-file-icon');

    previewImg.style.display = 'none';
    previewVideo.style.display = 'none';
    previewIcon.style.display = 'none';
    if (source === 'drag-drop') {
        sourceLabel.textContent = '📥 Dropped';
    } else if (source === 'paste') {
        sourceLabel.textContent = '📋 Pasted';
    } else {
        sourceLabel.textContent = '📄 From Device';
    }

    filename.textContent = file.name;
    filesize.textContent = formatFileSize(file.size);
    const ext = getFileExtension(file.name);

    if (file.type.startsWith('image/')) {
        const reader = new FileReader();
        reader.onload = (e) => {
            previewImg.src = e.target.result;
            previewImg.style.display = 'block';
        };
        reader.readAsDataURL(file);
    } else if (file.type.startsWith('video/')) {
        const reader = new FileReader();
        reader.onload = (e) => {
            previewVideo.src = e.target.result;
            previewVideo.style.display = 'block';
        };
        reader.readAsDataURL(file);
    } else {
        previewIcon.style.display = 'block';
    }

    container.classList.add('active');
    console.log('[Preview] File selected:', file.name, formatFileSize(file.size));
}

function hideFilePreview() {
    selectedFile = null;
    const container = document.getElementById('file-preview-container');
    container.classList.remove('active');
    document.getElementById('file-input').value = '';
}

document.getElementById('in').addEventListener('paste', function (e) {
    const items = e.clipboardData?.items;
    if (!items) return;

    for (let i = 0; i < items.length; i++) {
        const item = items[i];

        if (item.kind === 'file') {
            const file = item.getAsFile();
            if (file) {
                e.preventDefault();
                processFileUpload(file, 'paste');
                break;
            }
        }
    }
});
document.getElementById('file-input').addEventListener('change', function () {
    if (this.files.length > 0) {
        processFileUpload(this.files[0], 'upload');
    }
});
document.getElementById('preview-remove-btn').addEventListener('click', hideFilePreview);
document.getElementById('upload-btn').addEventListener('click', function () {
    document.getElementById('file-input').click();
});
// ========== DRAG & DROP ==========
const dragDropOverlay = document.getElementById('drag-drop-overlay');
let isDraggingFile = false;
let dragLeaveTimeout = null;

document.addEventListener('dragenter', (e) => {
    if (e.dataTransfer?.types?.includes('Files')) {
        clearTimeout(dragLeaveTimeout);
        isDraggingFile = true;
        dragDropOverlay.classList.add('active');
    }
});
document.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.stopPropagation();
    clearTimeout(dragLeaveTimeout);
});
document.addEventListener('dragleave', (e) => {
    dragLeaveTimeout = setTimeout(() => {
        isDraggingFile = false;
        dragDropOverlay.classList.remove('active');
    }, 50);
});
document.addEventListener('drop', (e) => {
    e.preventDefault();
    e.stopPropagation();
    clearTimeout(dragLeaveTimeout);
    isDraggingFile = false;
    dragDropOverlay.classList.remove('active');

    const files = e.dataTransfer?.files;
    if (!files || files.length === 0) return;

    const file = files[0];
    processFileUpload(file, 'drag-drop');
});
// ========== LEAVE GROUP ==========
document.getElementById("leave-btn").addEventListener('click', function () {
    if (confirm("Warning: If you leave this group, it will be removed from your personal account. Are you sure?")) {
        isUnloading = true;
        fetch(`/api/groups/${GROUP_ID}/leave`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${GROUP_SESSION_TOKEN}` },
            credentials: 'include'
        }).then(response => {
            if (response.ok) {
                clearInterval(MEMBERS_UPDATE_INTERVAL);
                clearInterval(ONLINE_HEARTBEAT_INTERVAL);
                alert("You have left the group.");
                window.location.href = "/groups";
            } else {
                alert("Failed to leave group.");
                isUnloading = false;
            }
        }).catch(err => {
            console.error("Leave group error:", err);
            alert("An error occurred.");
            isUnloading = false;
        });
    }
});

window.addEventListener('beforeunload', function () {
    if (!isUnloading) {
        clearInterval(MEMBERS_UPDATE_INTERVAL);
        clearInterval(ONLINE_HEARTBEAT_INTERVAL);
    }
});
// ========== INITIALIZATION ==========
console.log('[Init] Starting group chat initialization...');
if (initAuth()) {
    console.log('[Init] Auth successful, chat setup will load history...');
    // loadHistory() is now called from setupChat() after loadMembers() completes
} else {
    console.error('[Init] Auth failed');
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

// Initialize Push Notifications
initPushNotifications();
