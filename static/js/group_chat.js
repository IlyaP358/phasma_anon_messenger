// ========== VOICE MESSAGES ==========
let mediaRecorder = null;
let audioChunks = [];
let recordingStartTime = null;
let recordingInterval = null;
const recordingContainer = document.getElementById('recording-container');
const inputRow = document.getElementById('input-row');
const recordingTimeDisplay = document.getElementById('recording-time');
const btnMic = document.getElementById('btn-mic');
const btnCancelRecording = document.getElementById('btn-cancel-recording');
const btnSendRecording = document.getElementById('btn-send-recording');

// ========== EMOJI LOGIC STARTS HERE ==========
const EMOJI_DB_URL = '/static/emoji_database.json';
let emojiData = [];
let emojiCategories = {};
let emojiVariants = {}; // base_name -> [variant_objects]
let recentEmojis = [];

// Load recent emojis from local storage
function loadRecentEmojis() {
    const stored = localStorage.getItem('recent_emojis');
    if (stored) {
        try {
            recentEmojis = JSON.parse(stored);
        } catch (e) {
            recentEmojis = [];
        }
    }
}

function saveRecentEmoji(emoji) {
    // Remove if exists, then add to front
    recentEmojis = [emoji, ...recentEmojis.filter(e => e !== emoji)].slice(0, 20);
    localStorage.setItem('recent_emojis', JSON.stringify(recentEmojis));
}

// Fetch and process emoji database
async function loadEmojiDatabase() {
    try {
        const response = await fetch(EMOJI_DB_URL);
        const data = await response.json();
        emojiData = data.emojis;
        processEmojiData();
        renderCategories();
        renderEmojiGrid('Recent'); // Default to Recent
    } catch (error) {
        console.error('Failed to load emoji database:', error);
        document.getElementById('emoji-grid').innerHTML = '<div class="emoji-no-results">Failed to load emojis</div>';
    }
}

function processEmojiData() {
    emojiCategories = { 'Recent': [] };
    emojiVariants = {};

    // Helper to normalize name for variant checking
    // "OK hand: dark skin tone" -> base: "OK hand"
    const nameMap = new Map();
    emojiData.forEach(e => nameMap.set(e.name, e));

    emojiData.forEach(emoji => {
        // Handle Categories
        let cat = emoji.category;
        // Simplify category name: "People & Body (family)" -> "People & Body"
        if (cat.includes('(')) {
            cat = cat.split('(')[0].trim();
        }

        if (!emojiCategories[cat]) {
            emojiCategories[cat] = [];
        }

        // Handle Variants
        // Check if this is a variant
        if (emoji.name.includes(':')) {
            const parts = emoji.name.split(':');
            const potentialBaseName = parts[0].trim();

            if (nameMap.has(potentialBaseName)) {
                // This is a variant
                if (!emojiVariants[potentialBaseName]) {
                    emojiVariants[potentialBaseName] = [];
                }
                emojiVariants[potentialBaseName].push(emoji);
                return; // Don't add variants to main grid
            }
        }

        // Add to category if not a variant (or if base not found)
        emojiCategories[cat].push(emoji);
    });
}

// UI Elements
const emojiBtn = document.getElementById('emoji-btn');
const emojiModal = document.getElementById('emoji-picker-modal');
const emojiCloseBtn = document.getElementById('emoji-close-btn');
const emojiSearch = document.getElementById('emoji-search');
const emojiGrid = document.getElementById('emoji-grid');
const emojiTabsContainer = document.getElementById('emoji-categories-tabs');
const variantPopup = document.getElementById('emoji-variant-popup');
const variantGrid = document.getElementById('emoji-variant-grid');

let currentCategory = 'Recent';

// Event Listeners
emojiBtn.addEventListener('click', () => {
    emojiModal.classList.add('active');
    loadRecentEmojis();
    // Refresh Recent category
    if (currentCategory === 'Recent') {
        renderEmojiGrid('Recent');
    }
    emojiSearch.focus();
});

emojiCloseBtn.addEventListener('click', () => {
    emojiModal.classList.remove('active');
    variantPopup.style.display = 'none';
    emojiSearch.value = '';
});

// ========== MOBILE SIDEBAR TOGGLES ==========
const btnToggleGroups = document.getElementById('btn-toggle-groups');
const btnToggleMembers = document.getElementById('btn-toggle-members');
const groupsSidebar = document.querySelector('.groups-sidebar');
const membersSidebar = document.querySelector('.members-sidebar');

if (btnToggleGroups && groupsSidebar) {
    btnToggleGroups.addEventListener('click', (e) => {
        e.stopPropagation();
        groupsSidebar.classList.toggle('active');
        // Close members sidebar on mobile
        if (window.innerWidth <= 900 && membersSidebar) {
            membersSidebar.classList.remove('active');
        }
    });
}

if (btnToggleMembers && membersSidebar) {
    btnToggleMembers.addEventListener('click', (e) => {
        e.stopPropagation();
        membersSidebar.classList.toggle('active');
        // Close groups sidebar on mobile
        if (window.innerWidth <= 900 && groupsSidebar) {
            groupsSidebar.classList.remove('active');
        }
    });
}

// Close modal when clicking outside
document.addEventListener('click', (e) => {
    // Close emoji modal
    if (!emojiModal.contains(e.target) && e.target !== emojiBtn && !variantPopup.contains(e.target)) {
        emojiModal.classList.remove('active');
        variantPopup.style.display = 'none';
    }

    // Close sidebars on mobile when clicking outside
    if (window.innerWidth <= 900) {
        if (groupsSidebar && groupsSidebar.classList.contains('active') &&
            !groupsSidebar.contains(e.target) && e.target !== btnToggleGroups) {
            groupsSidebar.classList.remove('active');
        }
        if (membersSidebar && membersSidebar.classList.contains('active') &&
            !membersSidebar.contains(e.target) && e.target !== btnToggleMembers) {
            membersSidebar.classList.remove('active');
        }
    }
});

// Search
emojiSearch.addEventListener('input', () => {
    const query = emojiSearch.value.toLowerCase();
    variantPopup.style.display = 'none';

    if (!query) {
        renderEmojiGrid(currentCategory);
        return;
    }

    // Highlight no tabs during search
    document.querySelectorAll('.emoji-tab').forEach(t => t.classList.remove('active'));
    renderSearchResults(query);
});

function renderCategories() {
    emojiTabsContainer.innerHTML = '';

    // Define icons/labels for known categories to make it look nicer
    const categoryIcons = {
        'Recent': '⏱️',
        'Smileys & Emotion': '😀',
        'People & Body': '👋',
        'Animals & Nature': '🐻',
        'Food & Drink': '🍔',
        'Travel & Places': '🚗',
        'Activities': '⚽',
        'Objects': '💡',
        'Symbols': '❤️',
        'Flags': '🏁'
    };

    // Ensure Recent is first, then others
    const cats = ['Recent', ...Object.keys(emojiCategories).filter(c => c !== 'Recent')];

    cats.forEach(cat => {
        const btn = document.createElement('button');
        btn.className = 'emoji-tab';
        if (cat === currentCategory) btn.classList.add('active');
        btn.textContent = categoryIcons[cat] || cat.substring(0, 2); // Fallback to first 2 chars
        btn.title = cat;

        btn.addEventListener('click', () => {
            document.querySelectorAll('.emoji-tab').forEach(t => t.classList.remove('active'));
            btn.classList.add('active');
            currentCategory = cat;
            emojiSearch.value = '';
            variantPopup.style.display = 'none';
            renderEmojiGrid(cat);
        });

        emojiTabsContainer.appendChild(btn);
    });
}

function renderEmojiGrid(category) {
    emojiGrid.innerHTML = '';
    let emojis = [];

    if (category === 'Recent') {
        // Map recent strings back to objects if possible, or just use strings
        // But our logic uses objects for variants. 
        // Simple approach: Recent stores strings. We find the object.
        emojis = recentEmojis.map(char => {
            return emojiData.find(e => e.emoji === char) || { emoji: char, name: 'recent' };
        });

        if (emojis.length === 0) {
            emojiGrid.innerHTML = '<div class="emoji-no-results">No recent emojis</div>';
            return;
        }
    } else {
        emojis = emojiCategories[category] || [];
    }

    if (emojis.length === 0) {
        emojiGrid.innerHTML = '<div class="emoji-no-results">No emojis</div>';
        return;
    }

    emojis.forEach(emojiObj => {
        createEmojiElement(emojiObj, emojiGrid);
    });
}

function renderSearchResults(query) {
    emojiGrid.innerHTML = '';
    const results = emojiData.filter(e =>
        e.name.toLowerCase().includes(query) ||
        (e.shortname && e.shortname.toLowerCase().includes(query))
    ).slice(0, 100);

    if (results.length === 0) {
        emojiGrid.innerHTML = '<div class="emoji-no-results">No results</div>';
        return;
    }

    results.forEach(emojiObj => {
        createEmojiElement(emojiObj, emojiGrid);
    });
}

function createEmojiElement(emojiObj, container) {
    const item = document.createElement('div');
    item.className = 'emoji-item';
    item.textContent = emojiObj.emoji;
    item.title = emojiObj.name;

    // Check for variants
    // Note: Recent emojis might be variants themselves, so we check if *this* emoji name is a base for others
    // OR if it's a base name in our variants map
    const hasVariants = emojiVariants[emojiObj.name];

    if (hasVariants) {
        const indicator = document.createElement('span');
        indicator.style.position = 'absolute';
        indicator.style.bottom = '0';
        indicator.style.right = '0';
        indicator.style.fontSize = '8px';
        indicator.style.color = '#888';
        indicator.textContent = '▼';
        item.style.position = 'relative';
        item.appendChild(indicator);
    }

    item.addEventListener('click', (e) => {
        if (hasVariants) {
            showVariantPopup(emojiObj, hasVariants, item);
        } else {
            insertEmoji(emojiObj.emoji);
            saveRecentEmoji(emojiObj.emoji);
        }
    });

    container.appendChild(item);
}

function showVariantPopup(baseEmoji, variants, targetElement) {
    variantGrid.innerHTML = '';

    // Add base emoji first
    createVariantElement(baseEmoji);

    // Add variants
    variants.forEach(v => createVariantElement(v));

    // Show popup to measure its size
    variantPopup.style.display = 'block';
    variantPopup.style.visibility = 'hidden';

    // Get dimensions
    const rect = targetElement.getBoundingClientRect();
    const modalRect = emojiModal.getBoundingClientRect();
    const popupRect = variantPopup.getBoundingClientRect();

    // Calculate position relative to modal
    let top = rect.top - modalRect.top - popupRect.height - 5; // Try above first
    let left = rect.left - modalRect.left;

    // Check if popup goes above modal top
    if (top < 10) {
        // Show below instead
        top = rect.bottom - modalRect.top + 5;
    }

    // Check if popup goes beyond modal right edge
    if (left + popupRect.width > modalRect.width - 10) {
        left = modalRect.width - popupRect.width - 10;
    }

    // Check if popup goes beyond modal left edge
    if (left < 10) {
        left = 10;
    }

    // Apply position
    variantPopup.style.top = top + 'px';
    variantPopup.style.left = left + 'px';
    variantPopup.style.visibility = 'visible';
}

function createVariantElement(emojiObj) {
    const item = document.createElement('div');
    item.className = 'emoji-variant-item';
    item.textContent = emojiObj.emoji;
    item.title = emojiObj.name;
    item.addEventListener('click', (e) => {
        e.stopPropagation(); // Prevent closing immediately
        insertEmoji(emojiObj.emoji);
        saveRecentEmoji(emojiObj.emoji);
        variantPopup.style.display = 'none';
    });
    variantGrid.appendChild(item);
}

function insertEmoji(emojiChar) {
    const input = document.getElementById('in');
    const start = input.selectionStart;
    const end = input.selectionEnd;
    const text = input.value;

    input.value = text.substring(0, start) + emojiChar + text.substring(end);
    input.selectionStart = input.selectionEnd = start + emojiChar.length;
    input.focus();

    emojiModal.classList.remove('active');
}

// Initialize
loadEmojiDatabase();
// ========== EMOJI LOGIC ENDS HERE ==========

// ========== CORE CHAT VARIABLES ==========
let AUTH_TOKEN = null;
let CURRENT_USER = null;
let GROUP_SESSION_TOKEN = null;
let MEMBERS_UPDATE_INTERVAL = null;
let ONLINE_HEARTBEAT_INTERVAL = null;
let isUnloading = false;
let selectedFiles = [];
let isUploadingFile = false;
let messageIdToElementMap = new Map();
let pendingDeleteMessageId = null;
let memberProfilePics = new Map(); // Stores username -> has_profile_pic (bool)
let isSendingMessage = false;

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

    // Leave button
    const btnLeave = document.getElementById('leave-btn');
    const leaveModal = document.getElementById('leave-modal');
    const btnCancelLeave = document.getElementById('btn-cancel-leave');
    const btnConfirmLeave = document.getElementById('btn-confirm-leave');

    if (btnLeave && leaveModal) {
        btnLeave.addEventListener('click', () => {
            leaveModal.classList.add('active');
        });

        btnCancelLeave.addEventListener('click', () => {
            leaveModal.classList.remove('active');
        });

        btnConfirmLeave.addEventListener('click', () => {
            // Call API to leave group
            fetch(`/api/groups/${GROUP_ID}/leave`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${GROUP_SESSION_TOKEN}` },
                credentials: 'include'
            }).then(response => {
                if (response.ok) {
                    isUnloading = true;
                    clearInterval(MEMBERS_UPDATE_INTERVAL);
                    clearInterval(ONLINE_HEARTBEAT_INTERVAL);
                    window.location.href = "/groups";
                } else {
                    showNotification("Failed to leave group", 3000, true);
                    leaveModal.classList.remove('active');
                }
            }).catch(err => {
                console.error("Error leaving group:", err);
                showNotification("Error leaving group", 3000, true);
                leaveModal.classList.remove('active');
            });
        });

        // Close on outside click
        leaveModal.addEventListener('click', (e) => {
            if (e.target === leaveModal) {
                leaveModal.classList.remove('active');
            }
        });
    }

    // Invite Logic
    const inviteBtn = document.getElementById('invite-btn');
    const inviteModal = document.getElementById('invite-modal');
    const btnCloseInvite = document.getElementById('btn-close-invite');
    const btnCopyInvite = document.getElementById('btn-copy-invite');

    if (inviteBtn && inviteModal) {
        // Show invite button only if group is public AND NOT DM
        if (typeof GROUP_TYPE !== 'undefined' && GROUP_TYPE === 'public' && !IS_DM) {
            inviteBtn.style.display = 'inline-block';
        } else {
            inviteBtn.style.display = 'none';
        }

        inviteBtn.addEventListener('click', () => {
            inviteModal.classList.add('active');
            loadInvite();
        });

        btnCloseInvite.addEventListener('click', () => {
            inviteModal.classList.remove('active');
        });

        inviteModal.addEventListener('click', (e) => {
            if (e.target === inviteModal) {
                inviteModal.classList.remove('active');
            }
        });

        btnCopyInvite.addEventListener('click', () => {
            const link = document.getElementById('invite-link');
            link.select();
            document.execCommand('copy');
            btnCopyInvite.textContent = 'Copied!';
            setTimeout(() => {
                btnCopyInvite.textContent = 'Copy Link';
            }, 2000);
        });
    }

    // DM Specific UI Adjustments
    if (IS_DM) {
        // Hide settings button if it exists (or restrict options inside it)
        // Actually, we might want settings for "Delete Chat" or similar, but for now let's hide the type switcher and password change
        const typeOptions = document.querySelector('.group-type-options');
        if (typeOptions) typeOptions.style.display = 'none';

        const passSection = document.getElementById('settings-password-section');
        if (passSection) passSection.style.display = 'none';

        // Hide Group Code in sidebar list? handled in renderGroups
    }
}

// ... (rest of file) ...

// ========== PASSWORD CHANGE LOGIC ==========
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

        fetch(`/api/groups/${GROUP_ID}/update_password`, {
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

function loadInvite() {
    const loading = document.getElementById('invite-loading');
    const content = document.getElementById('invite-content');
    const error = document.getElementById('invite-error');
    const img = document.getElementById('invite-qr');
    const link = document.getElementById('invite-link');

    loading.style.display = 'block';
    content.style.display = 'none';
    error.textContent = '';

    fetch(`/api/groups/${GROUP_ID}/invite`, {
        headers: { 'Authorization': `Bearer ${GROUP_SESSION_TOKEN}` },
        credentials: 'include'
    })
        .then(r => r.json())
        .then(data => {
            loading.style.display = 'none';
            if (data.error) {
                error.textContent = data.error;
            } else {
                content.style.display = 'block';
                img.src = data.qr_code;
                link.value = data.invite_url;
            }
        })
        .catch(err => {
            loading.style.display = 'none';
            error.textContent = 'Failed to load invite';
            console.error(err);
        });
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
        const isDM = group.is_dm || false;

        let badgeHtml = '';
        if (group.unread_count > 0 && !isActive) {
            const countText = group.unread_count > 99 ? '99+' : group.unread_count;
            badgeHtml = `<span class="unread-badge">${countText}</span>`;
        }

        // Avatar for DM groups
        let avatarHtml = '';
        if (isDM && group.opponent_username) {
            avatarHtml = `<img src="/user/profile-pic/${group.opponent_username}" alt="Avatar" style="width: 32px; height: 32px; border-radius: 50%; margin-right: 8px; object-fit: cover; flex-shrink: 0;">`;
        } else if (isDM) {
            avatarHtml = `<img src="/static/unknown_user_phasma_icon.png" alt="Avatar" style="width: 32px; height: 32px; border-radius: 50%; margin-right: 8px; object-fit: cover; flex-shrink: 0;">`;
        }

        const deleteBtnHtml = (isCreator && !isDM) ? `<button class="btn-delete-group fluent-btn secondary" style="font-size:10px; padding:4px 8px; min-height:24px;" data-group-id="${group.id}">Delete</button>` : '';

        html += `<div class="group-item${activeClass}" data-group-id="${group.id}" style="display: flex; align-items: center;">
          ${avatarHtml}
          <div style="flex: 1; min-width: 0;">
              <div class="group-name">
                  <span>${escapeHtml(group.name)}</span>
                  <div style="display:flex; align-items:center;">
                      ${badgeHtml}
                      ${deleteBtnHtml}
                  </div>
              </div>
              ${!isDM ? `<div class="group-code">#${group.code}</div>` : ''}
          </div>
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
        const isSelfCreator = (TEMPLATE_USER === CURRENT_USER && TEMPLATE_USER === member.username && isCreator); // Check if *I* am the creator
    });

    // Find creator username
    const creatorMember = members.find(m => m.role === 'creator');
    const amICreator = creatorMember && creatorMember.username === CURRENT_USER;

    // Show/Hide Settings Button based on role
    const settingsBtn = document.getElementById('btn-group-settings');
    if (settingsBtn) {
        settingsBtn.style.display = amICreator ? 'inline-block' : 'none';
    }

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

        // Kick Button (Only for creator, and cannot kick self)
        let kickBtn = '';
        if (amICreator && !isCurrentUser) {
            kickBtn = `<button class="btn-kick-member" data-username="${escapeHtml(member.username)}" title="Kick Member">Kick</button>`;
        }

        // Avatar for member
        const avatarSrc = member.has_profile_pic
            ? `/user/profile-pic/${member.username}`
            : '/static/unknown_user_phasma_icon.png';

        html += `
          <div class="${className}">
            <div style="display:flex; align-items:center; flex:1;">
                <img src="${avatarSrc}" alt="${escapeHtml(member.username)}" class="member-avatar">
                ${dot}<span class="member-username">${escapeHtml(member.username)}</span>${userLabel}${roleLabel}
            </div>
            ${kickBtn}
          </div>
        `;

        // Update profile pic cache
        memberProfilePics.set(member.username, member.has_profile_pic);
    });
    membersList.innerHTML = html;

    // Attach event listeners for kick buttons
    document.querySelectorAll('.btn-kick-member').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const username = btn.getAttribute('data-username');
            showKickModal(username);
        });
    });
}

// ========== KICK MEMBER LOGIC ==========
let memberToKick = null;
const kickModal = document.getElementById('kick-modal');

function showKickModal(username) {
    memberToKick = username;
    document.getElementById('kick-username').textContent = username;
    kickModal.classList.add('active');
}

if (kickModal) {
    document.getElementById('btn-cancel-kick').addEventListener('click', () => {
        kickModal.classList.remove('active');
        memberToKick = null;
    });

    document.getElementById('btn-confirm-kick').addEventListener('click', () => {
        if (!memberToKick) return;

        const btn = document.getElementById('btn-confirm-kick');
        const originalText = btn.textContent;
        btn.textContent = 'Kicking...';
        btn.disabled = true;

        fetch(`/api/groups/${GROUP_ID}/kick`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${GROUP_SESSION_TOKEN}`
            },
            body: JSON.stringify({ username: memberToKick }),
            credentials: 'include'
        })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    showSuccess(`User ${memberToKick} kicked`);
                    loadMembers(); // Refresh list
                    kickModal.classList.remove('active');
                } else {
                    showError(data.error || 'Failed to kick member');
                }
            })
            .catch(err => {
                console.error(err);
                showError('Failed to kick member');
            })
            .finally(() => {
                btn.textContent = originalText;
                btn.disabled = false;
                memberToKick = null;
            });
    });
}

// ========== GROUP SETTINGS LOGIC ==========
const settingsModal = document.getElementById('group-settings-modal');
const btnSettings = document.getElementById('btn-group-settings');
const settingsWarning = document.getElementById('settings-warning');

if (btnSettings && settingsModal) {
    btnSettings.addEventListener('click', () => {
        // Set current state
        const currentType = (typeof GROUP_TYPE !== 'undefined') ? GROUP_TYPE : 'public';
        const radio = document.querySelector(`input[name="settings-type"][value="${currentType}"]`);
        if (radio) radio.checked = true;

        // Show/Hide warning initially
        if (currentType === 'public') {
            // If currently public, switching to private shows warning.
            // But we only show warning if *selected* is private.
            // Let's handle change event.
        }

        settingsModal.classList.add('active');
    });

    document.getElementById('btn-close-settings').addEventListener('click', () => {
        settingsModal.classList.remove('active');
    });

    // Handle radio change to show warning
    document.querySelectorAll('input[name="settings-type"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            if (e.target.value === 'private' && GROUP_TYPE === 'public') {
                settingsWarning.style.display = 'block';
            } else {
                settingsWarning.style.display = 'none';
            }
        });
    });

    document.getElementById('btn-save-settings').addEventListener('click', () => {
        const newType = document.querySelector('input[name="settings-type"]:checked').value;
        if (newType === GROUP_TYPE) {
            settingsModal.classList.remove('active');
            return;
        }

        const btn = document.getElementById('btn-save-settings');
        btn.textContent = 'Saving...';
        btn.disabled = true;

        fetch(`/api/groups/${GROUP_ID}/update_type`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${GROUP_SESSION_TOKEN}`
            },
            body: JSON.stringify({ group_type: newType }),
            credentials: 'include'
        })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    showSuccess('Group settings updated');
                    // Update local variable
                    // We can't easily update the const GROUP_TYPE from template, but we can reload page or just update UI
                    // Reloading is safer to ensure everything syncs (like invite button visibility)
                    setTimeout(() => window.location.reload(), 1000);
                } else {
                    showError(data.error || 'Failed to update settings');
                    btn.textContent = 'Save';
                    btn.disabled = false;
                }
            })
            .catch(err => {
                console.error(err);
                showError('Failed to update settings');
                btn.textContent = 'Save';
                btn.disabled = false;
            });
    });
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
    let messageId = null;
    let afterId = data;

    // Try to extract ID first
    const idMatch = data.match(/^\[ID:(\d+)\]/);
    if (idMatch) {
        messageId = parseInt(idMatch[1], 10);
        afterId = data.substring(idMatch[0].length);
    }

    const timeMatch = afterId.match(/^\[(\d+)\]\s+/);
    if (!timeMatch) return null;
    const timestamp = parseInt(timeMatch[1], 10);
    const afterTime = afterId.substring(timeMatch[0].length);

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

    return { id: messageId, timestamp, username, content, urls };
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
    urlDiv.style.color = '#3BACFF';
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

            // Loading container
            const loadingContainer = document.createElement("div");
            loadingContainer.className = "image-loading-container";

            // Spinner
            const spinner = document.createElement("div");
            spinner.className = "image-spinner";
            loadingContainer.appendChild(spinner);

            const img = document.createElement("img");
            img.src = photoMatch[2];
            img.alt = "Photo";
            img.loading = "lazy";
            img.className = "loading"; // Start with opacity 0
            img.style.cursor = "pointer";

            img.onload = () => {
                spinner.remove();
                loadingContainer.classList.remove("image-loading-container");
                loadingContainer.style.minHeight = "auto";
                loadingContainer.style.background = "transparent";
                img.classList.remove("loading");
                img.classList.add("loaded");
            };

            img.onerror = () => {
                spinner.remove();
                loadingContainer.innerHTML = '<span style="color: #ff4b4b; font-size: 12px;">⚠️ Failed to load image</span>';
            };

            img.onclick = () => window.open(photoMatch[2], '_blank');

            loadingContainer.appendChild(img);
            photoDiv.appendChild(loadingContainer);
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

        // Check if content is a URL
        const urlRegex = /^(https?:\/\/[^\s]+)$/;
        if (urlRegex.test(parsed.content)) {
            const link = document.createElement("a");
            link.href = parsed.content;
            link.textContent = parsed.content;
            link.target = "_blank";
            link.style.color = "#0078d4"; // Blue color
            link.style.textDecoration = "underline";
            link.onclick = (e) => e.stopPropagation();
            textDiv.appendChild(link);

            if (parsed.urls && parsed.urls[parsed.content]) {
                textDiv.style.display = 'none'; // Hide text if preview exists
            }
        } else {
            textDiv.textContent = parsed.content;
        }

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

                // FIX: Ensure SSE starts even if group is empty
                if (!initialLoadDone) {
                    initialLoadDone = true;
                    if (!sseStarted) {
                        sseStarted = true;
                        startSSE();
                    }
                }
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

                        if (data.startsWith('USER_ONLINE:')) {
                            const username = data.substring(12).trim();
                            updateMemberStatus(username, true);
                            return;
                        }

                        if (data.startsWith('USER_OFFLINE:')) {
                            const username = data.substring(13).trim();
                            updateMemberStatus(username, false);
                            return;
                        }

                        if (data.startsWith('USER_JOINED:')) {
                            const username = data.substring(12).trim();
                            // Add to member list if not exists (reload members)
                            loadMembers();
                            // Show system message
                            const msgElement = createSystemMessage(`${username} joined the group`);
                            messagesContainer.appendChild(msgElement);
                            return;
                        }

                        if (data.startsWith('USER_LEFT:')) {
                            const username = data.substring(10).trim();
                            // Remove from member list
                            const memberElement = document.querySelector(`.member-item[data-username="${username}"]`);
                            if (memberElement) memberElement.remove();
                            // Show system message
                            const msgElement = createSystemMessage(`${username} left the group`);
                            messagesContainer.appendChild(msgElement);
                            return;
                        }

                        if (data.startsWith('USER_KICKED:')) {
                            const username = data.substring(12).trim();
                            // Remove from member list
                            const memberElement = document.querySelector(`.member-item[data-username="${username}"]`);
                            if (memberElement) memberElement.remove();

                            if (username === CURRENT_USER) {
                                alert('You have been kicked from the group.');
                                window.location.href = '/groups';
                            }
                            return;
                        }

                        if (data.startsWith('GROUP_UPDATE:')) {
                            // Reload page or update UI
                            // For type change, reload is safest to update invite UI etc
                            window.location.reload();
                            return;
                        }

                        const parsed = parseMessageData(data);
                        const msgId = (parsed && parsed.id) ? parsed.id : (Date.now() + Math.random());
                        const msgElement = createMessageElement(data, msgId);
                        messagesContainer.appendChild(msgElement);

                        // Play notification sound if message is not from current user and window is not focused
                        if (parsed && parsed.username !== CURRENT_USER) {
                            if (isWindowActive) {
                                markAsRead();
                            } else {
                                const audio = new Audio('/static/phasma_notification_sound.mp3');
                                audio.play().catch(e => console.log('Audio play failed:', e));
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

    if (selectedFiles.length > 0) {
        sendFile();
        return;
    }

    if (isSendingMessage) return;

    const text = document.getElementById('in').value;
    if (!text.trim()) return;
    $.ajax({
        url: `/group/${GROUP_ID}/post`,
        type: 'POST',
        headers: { 'Authorization': `Bearer ${GROUP_SESSION_TOKEN}` },
        data: { message: text },
        beforeSend: function () {
            isSendingMessage = true;
        },
        success: function () {
            document.getElementById('in').value = '';
            isSendingMessage = false;
        },
        error: function (xhr) {
            isSendingMessage = false;
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
    if (!selectedFiles || selectedFiles.length === 0) return;
    if (isUploadingFile) return;
    isUploadingFile = true;

    const totalFiles = selectedFiles.length;
    let uploadedCount = 0;
    let errorCount = 0;

    // Helper to upload single file
    const uploadSingle = (file) => {
        return new Promise((resolve, reject) => {
            const formData = new FormData();
            formData.append('file', file);
            $.ajax({
                url: `/group/${GROUP_ID}/upload`,
                type: 'POST',
                headers: { 'Authorization': `Bearer ${GROUP_SESSION_TOKEN}` },
                data: formData,
                processData: false,
                contentType: false,
                success: function (response) {
                    resolve(response);
                },
                error: function (xhr) {
                    reject(xhr);
                }
            });
        });
    };

    for (let i = 0; i < totalFiles; i++) {
        const file = selectedFiles[i];
        try {
            await uploadSingle(file);
            uploadedCount++;
        } catch (e) {
            console.error(`Failed to upload ${file.name}`, e);
            errorCount++;

            // Try to extract error message
            let errMsg = 'Unknown error';
            if (e.responseText) {
                try {
                    const resp = JSON.parse(e.responseText);
                    errMsg = resp.message || resp.error || errMsg;
                } catch (jsonErr) { }
            }
            showError(`✗ Failed to upload ${file.name}: ${errMsg}`);
        }
    }

    isUploadingFile = false;
    hideFilePreview();

    if (errorCount === 0) {
        console.log(`[Upload] All ${totalFiles} files sent successfully`);
    } else {
        showError(`Uploaded ${uploadedCount}/${totalFiles} files. ${errorCount} failed.`);
    }
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

function processFileUpload(filesInput, source = 'upload') {
    let files = [];
    if (filesInput instanceof FileList) {
        files = Array.from(filesInput);
    } else if (Array.isArray(filesInput)) {
        files = filesInput;
    } else if (filesInput instanceof File) {
        files = [filesInput];
    }

    if (files.length === 0) return;

    if (files.length > 10) {
        showError('✗ Maximum 10 files allowed.');
        return;
    }

    const validFiles = [];
    for (const file of files) {
        const ext = getFileExtension(file.name);
        if (!validateFileExtension(ext)) {
            showError(`✗ File format ".${ext}" not allowed.`);
            continue;
        }

        if (!validateFileSize(file, ext)) {
            const maxSize = MAX_FILE_SIZES[ext] || 10;
            showError(`✗ File ${file.name} too large. Max: ${maxSize}MB`);
            continue;
        }

        if (file.size < 100) {
            showError(`✗ File ${file.name} too small.`);
            continue;
        }
        validFiles.push(file);
    }

    if (validFiles.length > 0) {
        showFilesPreview(validFiles, source);
    }
}

function showFilesPreview(files, source = 'upload') {
    selectedFiles = files;
    const container = document.getElementById('file-preview-container');
    const filename = document.getElementById('preview-filename');
    const filesize = document.getElementById('preview-filesize');
    const sourceLabel = document.getElementById('preview-source');
    const previewImg = document.getElementById('preview-img');
    const previewVideo = document.getElementById('preview-video');
    const previewIcon = document.getElementById('preview-file-icon');
    container.innerHTML = ''; // Clear existing

    if (files.length === 0) {
        container.classList.remove('active');
        return;
    }

    files.forEach((file, index) => {
        const item = document.createElement('div');
        item.className = 'preview-item';

        // Remove button
        const removeBtn = document.createElement('button');
        removeBtn.className = 'preview-remove-btn';
        removeBtn.innerHTML = '✕';
        removeBtn.onclick = (e) => {
            e.stopPropagation();
            removeFile(index);
        };
        item.appendChild(removeBtn);

        // Content
        if (file.type.startsWith('image/')) {
            const img = document.createElement('img');
            const reader = new FileReader();
            reader.onload = (e) => {
                img.src = e.target.result;
            };
            reader.readAsDataURL(file);
            item.appendChild(img);
        } else if (file.type.startsWith('video/')) {
            const video = document.createElement('video');
            const reader = new FileReader();
            reader.onload = (e) => {
                video.src = e.target.result;
            };
            reader.readAsDataURL(file);
            item.appendChild(video);
        } else {
            const placeholder = document.createElement('div');
            placeholder.className = 'file-icon-placeholder';

            const icon = document.createElement('img');
            icon.src = '/static/phasma_file.png';

            const name = document.createElement('div');
            name.textContent = file.name.length > 10 ? file.name.substring(0, 8) + '...' : file.name;

            const size = document.createElement('div');
            size.textContent = formatFileSize(file.size);
            size.style.fontSize = '9px';
            size.style.color = '#888';

            placeholder.appendChild(icon);
            placeholder.appendChild(name);
            placeholder.appendChild(size);
            item.appendChild(placeholder);
        }

        container.appendChild(item);
    });

    container.classList.add('active');
    console.log('[Preview] Files selected:', files.length);
}

function removeFile(index) {
    if (index >= 0 && index < selectedFiles.length) {
        selectedFiles.splice(index, 1);
        showFilesPreview(selectedFiles, 'update');

        // Update file input if empty (optional, but good for consistency)
        if (selectedFiles.length === 0) {
            document.getElementById('file-input').value = '';
        }
    }
}

function hideFilePreview() {
    selectedFiles = [];
    const container = document.getElementById('file-preview-container');
    container.classList.remove('active');
    container.innerHTML = '';
    document.getElementById('file-input').value = '';
}

document.getElementById('in').addEventListener('paste', function (e) {
    const items = e.clipboardData?.items;
    if (!items) return;

    const files = [];
    for (let i = 0; i < items.length; i++) {
        const item = items[i];
        if (item.kind === 'file') {
            const file = item.getAsFile();
            if (file) files.push(file);
        }
    }

    if (files.length > 0) {
        e.preventDefault();
        processFileUpload(files, 'paste');
    }
});
document.getElementById('file-input').addEventListener('change', function () {
    if (this.files.length > 0) {
        processFileUpload(this.files, 'upload');
    }
});
// Removed static listener for preview-remove-btn since it's dynamic now
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

    processFileUpload(files, 'drag-drop');
});


window.addEventListener('beforeunload', function () {
    if (!isUnloading) {
        clearInterval(MEMBERS_UPDATE_INTERVAL);
        clearInterval(ONLINE_HEARTBEAT_INTERVAL);

        // Mark all messages as read before leaving
        try {
            navigator.sendBeacon(`/api/groups/${GROUP_ID}/mark-read`, new Blob([JSON.stringify({})], { type: 'application/json' }));
        } catch (e) {
            console.warn('[Unload] Failed to mark as read:', e);
        }
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

// ========== SSE (Real-time Updates) ==========
function playNotificationSound() {
    const audio = document.getElementById('notification-sound');
    if (audio) {
        audio.play().catch(e => console.log('Audio play failed (user interaction needed?):', e));
    }
}

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
            // Play notification sound only if the update is for a different group
            // (current group messages already play sound via WebSocket handler)
            if (data.group_id && data.group_id !== GROUP_ID) {
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

// ========== SMART UNREAD LOGIC ==========
let isWindowActive = document.visibilityState === 'visible' && document.hasFocus();

function markAsRead() {
    if (!isWindowActive) return;

    fetch(`/api/groups/${GROUP_ID}/mark-read`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${GROUP_SESSION_TOKEN}` },
        credentials: 'include'
    }).catch(err => console.error('[Read] Failed to mark as read:', err));
}

document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
        isWindowActive = true;
        markAsRead();
    } else {
        isWindowActive = false;
    }
});

window.addEventListener('focus', () => {
    isWindowActive = true;
    markAsRead();
});

window.addEventListener('blur', () => {
    isWindowActive = false;
});

// Initial check
if (isWindowActive) {
    markAsRead();
}

// Initialize SSE and Push Notifications
initSSE();
initPushNotifications();

// ========== VOICE MESSAGE FUNCTIONS ==========
async function startRecording() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        showError("⚠️ Microphone not supported. HTTPS or localhost required.");
        return;
    }

    try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        mediaRecorder = new MediaRecorder(stream, { mimeType: 'audio/webm' }); // Prefer webm
        audioChunks = [];

        mediaRecorder.ondataavailable = event => {
            if (event.data.size > 0) {
                audioChunks.push(event.data);
            }
        };

        mediaRecorder.start();

        // UI Updates
        if (inputRow) inputRow.style.display = 'none';
        if (recordingContainer) recordingContainer.style.display = 'flex';
        recordingStartTime = Date.now();
        updateRecordingTimer();
        recordingInterval = setInterval(updateRecordingTimer, 100);

    } catch (err) {
        console.error("Error accessing microphone:", err);
        if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
            showError("⚠️ Access denied. Please tap the lock icon 🔒 in your address bar and Allow Microphone.");
        } else if (err.name === 'NotFoundError') {
            showError("⚠️ No microphone found on this device.");
        } else {
            showError(`⚠️ Microphone error: ${err.message || err.name}`);
        }
    }
}

function updateRecordingTimer() {
    const elapsed = Date.now() - recordingStartTime;
    const seconds = Math.floor(elapsed / 1000);
    const ms = Math.floor((elapsed % 1000) / 10); // 2 digits
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    if (recordingTimeDisplay) {
        recordingTimeDisplay.textContent = `${minutes}:${secs.toString().padStart(2, '0')},${ms.toString().padStart(2, '0')}`;
    }
}

function cancelRecording() {
    if (mediaRecorder && mediaRecorder.state !== 'inactive') {
        mediaRecorder.stop();
    }
    stopRecordingUI();
}

function stopRecordingUI() {
    clearInterval(recordingInterval);
    if (inputRow) inputRow.style.display = 'flex';
    if (recordingContainer) recordingContainer.style.display = 'none';
    if (mediaRecorder && mediaRecorder.stream) {
        mediaRecorder.stream.getTracks().forEach(track => track.stop());
    }
    mediaRecorder = null;
    audioChunks = [];
}

function stopAndSendRecording() {
    if (!mediaRecorder || mediaRecorder.state === 'inactive') return;

    mediaRecorder.onstop = () => {
        const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
        // Use .weba extension as planned
        const audioFile = new File([audioBlob], "voice.weba", { type: "audio/webm" });

        // Send file
        selectedFiles = [audioFile];
        sendFile();
        stopRecordingUI();
    };

    mediaRecorder.stop();
}

// Event Listeners for Voice Messages
console.log('[Voice] Attaching event listeners...');
console.log('[Voice] btnMic:', btnMic);
console.log('[Voice] btnCancelRecording:', btnCancelRecording);
console.log('[Voice] btnSendRecording:', btnSendRecording);

if (btnMic) {
    btnMic.addEventListener('click', startRecording);
    console.log('[Voice] Microphone button listener attached');
} else {
    console.error('[Voice] Microphone button not found!');
}

if (btnCancelRecording) {
    btnCancelRecording.addEventListener('click', cancelRecording);
    console.log('[Voice] Cancel button listener attached');
} else {
    console.error('[Voice] Cancel button not found!');
}

if (btnSendRecording) {
    btnSendRecording.addEventListener('click', stopAndSendRecording);
    console.log('[Voice] Send button listener attached');
} else {
    console.error('[Voice] Send button not found!');
}


// ========== ONLINE STATUS UPDATES ==========
function updateMemberStatus(username, isOnline) {
    const memberElement = document.querySelector(`.member-item[data-username="${username}"]`);
    if (memberElement) {
        const statusDot = memberElement.querySelector('.status-dot');
        if (statusDot) {
            statusDot.className = `status-dot ${isOnline ? 'online' : 'offline'}`;
        }
    }
}

function createSystemMessage(text) {
    const msg = document.createElement("div");
    msg.className = "message system-message";
    msg.style.textAlign = "center";
    msg.style.color = "#888";
    msg.style.fontSize = "0.8em";
    msg.style.margin = "10px 0";
    msg.textContent = text;
    return msg;
}

// Auto-resize textarea
const input = document.getElementById('in');
// inputRow is already defined globally

function autoResize() {
    if (!input) return;
    input.style.height = 'auto';
    input.style.height = input.scrollHeight + 'px';

    // Toggle expanded class based on content or focus
    if (window.innerWidth <= 900) {
        if (input.value.trim().length > 0 || document.activeElement === input) {
            inputRow.classList.add('input-expanded');
        } else {
            inputRow.classList.remove('input-expanded');
        }
    }
}

if (input) {
    input.addEventListener('input', autoResize);
    input.addEventListener('focus', () => {
        if (window.innerWidth <= 900) inputRow.classList.add('input-expanded');
    });
    input.addEventListener('blur', () => {
        // Delay to allow click on send button
        setTimeout(() => {
            if (input.value.trim().length === 0) {
                inputRow.classList.remove('input-expanded');
            }
        }, 200);
    });

    // Initial resize
    autoResize();
}

// Capacitor Back Button
if (window.Capacitor) {
    const App = window.Capacitor.Plugins.App;
    if (App) {
        App.addListener('backButton', ({ canGoBack }) => {
            // If sidebar is open, close it
            if (groupsSidebar && groupsSidebar.classList.contains('active')) {
                groupsSidebar.classList.remove('active');
                return;
            }
            if (membersSidebar && membersSidebar.classList.contains('active')) {
                membersSidebar.classList.remove('active');
                return;
            }

            // If emoji modal is open, close it
            if (emojiModal && emojiModal.classList.contains('active')) {
                emojiModal.classList.remove('active');
                return;
            }

            // Default behavior: go back to groups list
            window.location.href = '/groups';
        });
    }
}
