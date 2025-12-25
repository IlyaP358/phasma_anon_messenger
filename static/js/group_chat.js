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

// ========== CALL MANAGER (WebRTC) ==========
class CallManager {
    constructor() {
        console.log('[Call] Initializing CallManager');

        this.peerConnection = null;
        this.localStream = null;
        this.remoteStream = null;
        this.isCaller = false;
        this.peerUsername = null;
        this.signalingInterval = null;
        this.isCallActive = false;
        this.pendingOffer = null;
        this.pendingCandidates = [];
        this.autoAction = null; // 'accept' or 'decline' from notification
        this.autoActionCaller = null;

        // STUN servers
        this.iceServers = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' },
                { urls: 'stun:stun2.l.google.com:19302' }
            ]
        };

        this.initUI();
        this.startSignalingLoop();

        console.log('[Call] CallManager initialized');
    }

    initUI() {
        console.log('[Call] initUI: IS_DM =', IS_DM, ', GROUP_NAME =', GROUP_NAME);

        this.btnCall = document.getElementById('btn-call-user');
        this.overlay = document.getElementById('call-overlay');
        this.localVideo = document.getElementById('local-video');
        this.remoteVideo = document.getElementById('remote-video');
        this.statusText = document.getElementById('call-status');

        // Incoming call modal
        this.incomingModal = document.getElementById('incoming-call-modal');
        this.btnAccept = document.getElementById('btn-accept-call');
        this.btnDecline = document.getElementById('btn-decline-call');
        this.callerNameDisplay = document.getElementById('caller-name');

        // Controls
        this.btnEnd = document.getElementById('btn-end-call');
        this.btnMic = document.getElementById('btn-toggle-mic');
        this.btnCam = document.getElementById('btn-toggle-cam');

        // Handlers
        if (this.btnCall) {
            console.log('[Call] btnCall found, IS_DM =', IS_DM);
            if (IS_DM) {
                console.log('[Call] IS_DM is true, showing call button');
                this.btnCall.style.display = 'block';
                this.btnCall.onclick = () => this.startCall();
            } else {
                console.log('[Call] IS_DM is false, hiding call button');
                this.btnCall.style.display = 'none';
            }
        } else {
            console.log('[Call] btnCall NOT FOUND in DOM');
        }

        this.btnEnd.onclick = () => this.endCall();

        this.btnMic.onclick = () => {
            if (this.localStream) {
                const track = this.localStream.getAudioTracks()[0];
                if (track) {
                    track.enabled = !track.enabled;
                    this.btnMic.textContent = track.enabled ? '🎤' : '🔇';
                    this.btnMic.style.background = track.enabled ? 'rgba(255,255,255,0.2)' : 'rgba(255,0,0,0.5)';
                } else {
                    showError('ℹ️ No microphone available');
                }
            }
        };

        this.btnCam.onclick = () => {
            if (this.localStream) {
                const track = this.localStream.getVideoTracks()[0];
                if (track) {
                    track.enabled = !track.enabled;
                    this.btnCam.textContent = track.enabled ? '📷' : '🚫';
                    this.btnCam.style.background = track.enabled ? 'rgba(255,255,255,0.2)' : 'rgba(255,0,0,0.5)';
                } else {
                    showError('ℹ️ No camera available');
                }
            }
        };

        this.btnAccept.onclick = () => this.acceptCall();
        this.btnDecline.onclick = () => {
            // Notify caller that we declined
            try {
                this.sendSignal('decline', {});
            } catch (e) {
                console.warn('[Call] Failed to send decline signal', e);
            }

            this.incomingModal.classList.remove('active');
            const ringtone = document.getElementById('ringtone-sound');
            if (ringtone) {
                ringtone.pause();
                ringtone.currentTime = 0;
            }
        };
    }

    async getMedia() {
        console.log('[Call] Requesting media access...');

        // If we already have a local stream, reuse it
        if (this.localStream) {
            console.log('[Call] Using existing local stream');
            return true;
        }

        try {
            // First try with video and audio (optimal quality)
            try {
                console.log('[Call] Attempting with video + audio (optimal)...');
                this.localStream = await navigator.mediaDevices.getUserMedia({
                    audio: {
                        echoCancellation: true,
                        noiseSuppression: true,
                        autoGainControl: true
                    },
                    video: {
                        width: { ideal: 1280 },
                        height: { ideal: 720 },
                        facingMode: 'user'
                    }
                });
                console.log('[Call] ✅ Media access granted with video + audio (optimal)');
                this.localVideo.srcObject = this.localStream;
                return true;
            } catch (e1) {
                console.warn('[Call] Optimal video+audio failed:', e1.name);

                // Try basic video + audio
                try {
                    console.log('[Call] Attempting with video + audio (basic)...');
                    this.localStream = await navigator.mediaDevices.getUserMedia({
                        audio: true,
                        video: true
                    });
                    console.log('[Call] ✅ Media access granted with video + audio (basic)');
                    this.localVideo.srcObject = this.localStream;
                    return true;
                } catch (e2) {
                    console.warn('[Call] Basic video+audio failed:', e2.name);

                    // Try audio only (no camera available)
                    try {
                        console.log('[Call] Attempting audio-only (no camera)...');
                        this.localStream = await navigator.mediaDevices.getUserMedia({
                            audio: true,
                            video: false
                        });
                        console.log('[Call] ✅ Media access granted with audio-only');
                        // Don't set video srcObject for audio-only
                        showError('ℹ️ Joined call with audio only (no camera detected)');
                        return true;
                    } catch (e3) {
                        console.warn('[Call] Audio-only failed:', e3.name);

                        // Last resort: allow joining without any media
                        if (e3.name === 'NotFoundError' || e3.name === 'NotReadableError' || e3.name === 'NotAllowedError') {
                            console.warn('[Call] No media devices available - proceeding without local media');
                            try {
                                // Create empty MediaStream as placeholder
                                this.localStream = new MediaStream();
                                showError('ℹ️ Joined call without camera/microphone (receive-only mode)');
                                return true;
                            } catch (ex) {
                                console.error('[Call] Failed to create empty MediaStream fallback', ex);
                                showError('❌ Failed to initialize call');
                                return false;
                            }
                        }

                        // Re-throw if it's a different error
                        throw e3;
                    }
                }
            }
        } catch (e) {
            console.error('[Call] Error accessing media:', e.name, '-', e.message);

            // Provide specific error messages
            let errorMsg = '❌ Could not access camera/microphone.';
            if (e.name === 'NotAllowedError') {
                errorMsg += ' Permission denied. Please check browser settings.';
            } else if (e.name === 'NotReadableError') {
                errorMsg += ' Device is busy. Close other apps using camera/microphone.';
            } else if (e.name === 'OverconstrainedError') {
                errorMsg += ' Device does not meet quality requirements.';
            } else if (e.name === 'TypeError') {
                errorMsg += ' Invalid media request.';
            } else {
                errorMsg += ' Please allow permissions and try again.';
            }

            showError(errorMsg);
            return false;
        }
    }

    createPeerConnection() {
        console.log('[Call] Creating peer connection');

        this.peerConnection = new RTCPeerConnection(this.iceServers);

        this.peerConnection.onicecandidate = (event) => {
            console.log('[Call] ICE candidate generated');
            if (event.candidate) {
                // Send a plain-serializable candidate object to the server
                try {
                    const cand = (typeof event.candidate.toJSON === 'function') ? event.candidate.toJSON() : event.candidate;
                    this.sendSignal('candidate', cand);
                } catch (ex) {
                    // Fallback: send the raw candidate fields
                    this.sendSignal('candidate', {
                        candidate: event.candidate.candidate,
                        sdpMid: event.candidate.sdpMid,
                        sdpMLineIndex: event.candidate.sdpMLineIndex
                    });
                }
            }
        };

        this.peerConnection.ontrack = (event) => {
            console.log('[Call] Received remote track:', event.track.kind);
            this.remoteVideo.srcObject = event.streams[0];
            this.remoteStream = event.streams[0];
            this.statusText.style.display = 'none';
        };

        this.peerConnection.onconnectionstatechange = () => {
            const state = this.peerConnection.connectionState;
            console.log('[Call] Connection state changed:', state);

            if (state === 'disconnected' ||
                state === 'failed' ||
                state === 'closed') {
                console.log('[Call] Connection ended, closing call');
                this.endCall(false); // Don't send signal loop, just close UI
            } else if (state === 'connected') {
                console.log('[Call] Connection established successfully!');
            }
        };

        this.peerConnection.onicegatheringstatechange = () => {
            console.log('[Call] ICE gathering state:', this.peerConnection.iceGatheringState);
        };

        this.peerConnection.onsignalingstatechange = () => {
            console.log('[Call] Signaling state:', this.peerConnection.signalingState);
        };

        // Add local tracks
        if (this.localStream) {
            console.log('[Call] Adding local tracks to peer connection');
            this.localStream.getTracks().forEach(track => {
                console.log('[Call] Adding track:', track.kind);
                this.peerConnection.addTrack(track, this.localStream);
            });
        } else {
            console.warn('[Call] No local stream to add');
        }
        // Attempt to apply any buffered candidates if remote description already present
        try {
            if (this.pendingCandidates && this.pendingCandidates.length > 0 && this.peerConnection && this.peerConnection.remoteDescription) {
                this.pendingCandidates.forEach(async (candData) => {
                    try {
                        const c = new RTCIceCandidate({
                            candidate: candData.candidate || candData,
                            sdpMLineIndex: candData.sdpMLineIndex || 0,
                            sdpMid: candData.sdpMid || ''
                        });
                        await this.peerConnection.addIceCandidate(c);
                        console.log('[Call] Applied buffered ICE candidate during createPeerConnection');
                    } catch (e) {
                        console.warn('[Call] Failed to apply buffered candidate during createPeerConnection', e);
                    }
                });
                this.pendingCandidates = [];
            }
        } catch (e) {
            console.warn('[Call] apply pending candidates error in createPeerConnection', e);
        }
    }

    applyPendingCandidates() {
        if (!this.pendingCandidates || !this.peerConnection) return;
        if (!this.peerConnection.remoteDescription) return; // need remote description first
        this.pendingCandidates.forEach(async (candData) => {
            try {
                const candidate = new RTCIceCandidate({
                    candidate: candData.candidate || candData,
                    sdpMLineIndex: candData.sdpMLineIndex || 0,
                    sdpMid: candData.sdpMid || ''
                });
                await this.peerConnection.addIceCandidate(candidate);
                console.log('[Call] Applied buffered ICE candidate');
            } catch (e) {
                console.warn('[Call] Failed to apply buffered candidate', e);
            }
        });
        this.pendingCandidates = [];
    }

    async startCall() {
        console.log('[Call] startCall() called, IS_DM =', IS_DM);

        if (!IS_DM) {
            console.error('[Call] Call only works in DM, but IS_DM =', IS_DM);
            showError('❌ Calls only available in Direct Messages');
            return;
        }

        // Use opponent_username directly from template
        this.peerUsername = OPPONENT_USERNAME;

        if (!this.peerUsername) {
            console.error('[Call] No opponent_username available');
            showError('❌ Cannot determine peer');
            return;
        }

        console.log(`[Call] Starting call with ${this.peerUsername}`);

        this.isCaller = true;
        this.isCallActive = true;
        this.overlay.style.display = 'flex';
        this.statusText.textContent = 'Calling ' + this.peerUsername + '...';
        this.statusText.style.display = 'block';

        // Get media access with detailed logging
        console.log('[Call] Getting media for outgoing call...');
        const mediaOk = await this.getMedia();

        if (!mediaOk) {
            console.error('[Call] Failed to get media access for outgoing call');
            this.endCall();
            return;
        }

        console.log('[Call] Media obtained, creating peer connection...');

        try {
            this.createPeerConnection();

            console.log('[Call] Creating offer...');
            const offer = await this.peerConnection.createOffer();

            console.log('[Call] Setting local description...');
            await this.peerConnection.setLocalDescription(offer);

            console.log('[Call] Sending offer signal...');
            // Send only the plain SDP/text to avoid circular/non-serializable objects
            this.sendSignal('offer', { type: offer.type, sdp: offer.sdp });

            console.log('[Call] Call initiated successfully!');
        } catch (e) {
            console.error('[Call] Error creating offer:', e.name, '-', e.message);
            showError('❌ Failed to create call offer: ' + e.message);
            this.endCall();
        }
    }

    async handleSignal(signal) {
        console.log(`[Call] Received signal type: ${signal.type} from ${signal.sender}`);

        if (signal.type === 'offer') {
            // Incoming call
            console.log('[Call] Incoming call from', signal.sender);

            if (this.isCallActive) {
                console.warn('[Call] Already in call, rejecting incoming');
                return; // Busy
            }

            this.peerUsername = signal.sender;
            this.callerNameDisplay.textContent = this.peerUsername;
            this.incomingModal.classList.add('active');

            // Play ringtone sound
            const ringtone = document.getElementById('ringtone-sound');
            if (ringtone) {
                ringtone.currentTime = 0;
                ringtone.play().catch(e => console.log('[Call] Autoplay blocked', e));
            }

            // Store offer to handle later
            this.pendingOffer = signal.payload;
            console.log('[Call] Offer stored, waiting for user to accept');

            // If page was opened from notification with action param, auto-act
            if (this.autoAction) {
                // If caller restriction present, ensure it matches
                if (!this.autoActionCaller || this.autoActionCaller === signal.sender) {
                    console.log('[Call] Auto-action triggered:', this.autoAction);
                    if (this.autoAction === 'accept') {
                        // Allow a small delay to let UI settle
                        setTimeout(() => this.acceptCall(), 200);
                    } else if (this.autoAction === 'decline') {
                        try {
                            this.sendSignal('decline', {});
                        } catch (e) {
                            console.warn('[Call] Auto-decline failed', e);
                        }
                        this.incomingModal.classList.remove('active');
                        const ringtone = document.getElementById('ringtone-sound');
                        if (ringtone) {
                            ringtone.pause();
                            ringtone.currentTime = 0;
                        }
                    }
                    // Clear autoAction so it doesn't repeat
                    this.autoAction = null;
                    this.autoActionCaller = null;
                }
            }

        } else if (signal.type === 'answer') {
            console.log('[Call] Received answer');

            if (!this.isCallActive || !this.isCaller) {
                console.warn('[Call] Not expecting answer (not in call or not caller)');
                return;
            }

            if (!this.peerConnection) {
                console.error('[Call] No peer connection for answer');
                return;
            }

            try {
                const answerSD = new RTCSessionDescription({
                    type: 'answer',
                    sdp: signal.payload.sdp || signal.payload
                });
                await this.peerConnection.setRemoteDescription(answerSD);
                console.log('[Call] Answer set successfully');
                // After setting remote description, apply any buffered ICE candidates
                try { this.applyPendingCandidates(); } catch (e) { console.warn('[Call] applyPendingCandidates error', e); }
            } catch (e) {
                console.error('[Call] Error setting answer:', e);
            }

        } else if (signal.type === 'candidate') {
            console.log('[Call] Received ICE candidate');

            // If we don't yet have an active peer connection, buffer the candidate
            if ((!this.isCallActive || !this.peerConnection)) {
                try {
                    console.log('[Call] Buffering ICE candidate until peerConnection exists');
                    this.pendingCandidates.push(signal.payload);
                    return;
                } catch (e) {
                    console.warn('[Call] Failed to buffer candidate', e);
                }
            }

            if (this.isCallActive && this.peerConnection) {
                try {
                    // Candidate might be a plain object or IceCandidate
                    const candidateData = signal.payload;
                    const candidate = new RTCIceCandidate({
                        candidate: candidateData.candidate || candidateData,
                        sdpMLineIndex: candidateData.sdpMLineIndex || 0,
                        sdpMid: candidateData.sdpMid || ''
                    });
                    await this.peerConnection.addIceCandidate(candidate);
                    console.log('[Call] ICE candidate added');
                } catch (e) {
                    console.error('[Call] Error adding ICE candidate:', e);
                }
            } else {
                console.warn('[Call] Not in call to add ICE candidate');
            }
        } else {
            console.warn('[Call] Unknown signal type:', signal.type);
        }
    }

    async acceptCall() {
        console.log(`[Call] Accepting call from ${this.peerUsername}`);

        this.incomingModal.classList.remove('active');

        // Stop ringtone
        const ringtone = document.getElementById('ringtone-sound');
        if (ringtone) {
            ringtone.pause();
            ringtone.currentTime = 0;
        }

        if (!this.pendingOffer) {
            console.error('[Call] No pending offer to accept');
            showError('❌ Call offer lost');
            return;
        }

        this.isCaller = false;
        this.isCallActive = true;
        this.overlay.style.display = 'flex';
        this.statusText.textContent = 'Connecting...';
        this.statusText.style.display = 'block';

        // Get media access with detailed logging
        console.log('[Call] Getting media for accepting call...');
        const mediaOk = await this.getMedia();

        if (!mediaOk) {
            console.error('[Call] Failed to get media access for accepting call');
            this.endCall();
            return;
        }

        console.log('[Call] Media obtained, creating peer connection...');

        try {
            this.createPeerConnection();

            // Convert plain object to RTCSessionDescription if needed
            const offerData = this.pendingOffer;
            const offerSD = new RTCSessionDescription({
                type: 'offer',
                sdp: offerData.sdp || offerData
            });

            console.log('[Call] Setting remote description (offer)...');
            await this.peerConnection.setRemoteDescription(offerSD);
            // Apply any buffered ICE candidates now that remote is set
            try { this.applyPendingCandidates(); } catch (e) { console.warn('[Call] applyPendingCandidates error after setRemoteDescription', e); }

            console.log('[Call] Creating answer...');
            const answer = await this.peerConnection.createAnswer();

            console.log('[Call] Setting local description (answer)...');
            await this.peerConnection.setLocalDescription(answer);

            console.log('[Call] Sending answer signal...');
            // Send only the SDP text/type
            this.sendSignal('answer', { type: answer.type, sdp: answer.sdp });

            console.log('[Call] Call accepted successfully!');
        } catch (e) {
            console.error('[Call] Error accepting call:', e.name, '-', e.message);
            showError('❌ Failed to accept call: ' + e.message);
            this.endCall();
        }
    }

    endCall(notifyRemote = true) {
        console.log('[Call] Ending call');

        this.isCallActive = false;
        this.pendingOffer = null;

        try {
            // Notify remote peer if requested
            if (notifyRemote && this.peerUsername) {
                try {
                    this.sendSignal('hangup', {});
                } catch (e) {
                    console.warn('[Call] Failed to send hangup signal', e);
                }
            }
            // Stop ringtone
            const ringtone = document.getElementById('ringtone-sound');
            if (ringtone) {
                ringtone.pause();
                ringtone.currentTime = 0;
            }

            // Stop all local tracks and clear stream
            if (this.localStream) {
                console.log('[Call] Stopping local media tracks');
                this.localStream.getTracks().forEach(track => {
                    try {
                        console.log('[Call] Stopping track:', track.kind);
                        track.stop();
                    } catch (e) {
                        console.error('[Call] Error stopping track:', e);
                    }
                });
                this.localStream = null; // Clear reference
                console.log('[Call] Local stream cleared');
            }

            // Close peer connection
            if (this.peerConnection) {
                console.log('[Call] Closing peer connection');
                try {
                    this.peerConnection.close();
                } catch (e) {
                    console.error('[Call] Error closing peer connection:', e);
                }
                this.peerConnection = null; // Clear reference
            }

            // Clear UI
            this.overlay.style.display = 'none';
            this.localVideo.srcObject = null;
            this.remoteVideo.srcObject = null;
            this.statusText.style.display = 'none';
            this.incomingModal.classList.remove('active');

            console.log('[Call] Call cleanup completed');
        } catch (e) {
            console.error('[Call] Error during call cleanup:', e);
        }
    }

    sendSignal(type, payload) {
        if (!this.peerUsername) {
            console.error('[Call] Cannot send signal - no peer username');
            return;
        }

        console.log(`[Call] Sending ${type} signal to ${this.peerUsername}`);

        // Normalize payload to ensure it's JSON-serializable
        let payloadForSend = payload;
        try {
            if (payloadForSend && typeof payloadForSend === 'object') {
                // Use toJSON if available (RTCIceCandidate, etc.)
                if (typeof payloadForSend.toJSON === 'function') {
                    payloadForSend = payloadForSend.toJSON();
                }

                // If it's an SDP-like object, send only sdp/type
                if (payloadForSend.sdp) {
                    payloadForSend = { type: payloadForSend.type || type, sdp: payloadForSend.sdp };
                } else if (payloadForSend.candidate) {
                    // Candidate object
                    payloadForSend = {
                        candidate: payloadForSend.candidate,
                        sdpMid: payloadForSend.sdpMid,
                        sdpMLineIndex: payloadForSend.sdpMLineIndex
                    };
                } else {
                    // leave as-is (plain object)
                }
            }
        } catch (e) {
            console.warn('[Call] Failed to normalize signal payload, sending raw', e);
            payloadForSend = {};
        }

        fetch('/api/signal', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                receiver: this.peerUsername,
                type: type,
                payload: payloadForSend
            })
        })
            .then(r => {
                if (!r.ok) {
                    console.error(`[Call] Failed to send signal: ${r.status}`);
                    return r.json().then(data => {
                        throw new Error(data.error || 'Unknown error');
                    });
                }
                return r.json();
            })
            .then(data => {
                console.log(`[Call] Signal sent successfully:`, data);
            })
            .catch(e => {
                console.error(`[Call] Error sending signal:`, e);
            });
    }

    startSignalingLoop() {
        console.log('[Call] Starting signaling loop (polling every 1.5s)');

        // Poll every 1.5 seconds
        setInterval(async () => {
            try {
                const res = await fetch('/api/signals', { credentials: 'include' });

                if (!res.ok) {
                    console.warn(`[Call] Signals endpoint returned ${res.status}`);
                    return;
                }

                const data = await res.json();

                if (data.signals && data.signals.length > 0) {
                    console.log(`[Call] Received ${data.signals.length} signal(s)`);
                    data.signals.forEach(signal => this.handleSignal(signal));
                } else {
                    console.log('[Call] No new signals');
                }
            } catch (e) {
                console.error('[Call] Signaling loop error:', e);
            }
        }, 1500);
    }
}

// Initialize logic
const callManager = new CallManager();
// Handle notification action params (service-worker opens with ?action=accept|decline&caller=Name)
(() => {
    try {
        const params = new URLSearchParams(window.location.search);
        const act = params.get('action');
        const caller = params.get('caller');
        if (act === 'accept' || act === 'decline') {
            callManager.autoAction = act;
            if (caller) callManager.autoActionCaller = caller;
            console.log('[Call] Auto-action set from URL:', act, caller);
        }
    } catch (e) {
        console.warn('[Call] Failed to parse action params', e);
    }
})();
loadEmojiDatabase();

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
let loadingImages = new Map(); // Tracks loading images: {messageId: Set of image indices}

console.log('[Init] Group chat page loaded. Group ID:', GROUP_ID);

// App Loader
window.addEventListener('load', () => {
    // Minimum load time for effect
    setTimeout(() => {
        const loader = document.getElementById('app-loader');
        if (loader) loader.classList.add('hidden');
    }, 800);
});

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

// Track image loading for proper scroll behavior
function registerImageLoad(messageId, img) {
    if (!loadingImages.has(messageId)) {
        loadingImages.set(messageId, new Set());
    }

    const imageSet = loadingImages.get(messageId);
    const imageIndex = imageSet.size;
    imageSet.add(imageIndex);

    const onLoadOrError = () => {
        imageSet.delete(imageIndex);
        // If all images in this message are loaded
        if (imageSet.size === 0) {
            loadingImages.delete(messageId);
            // Check if this is the newest message and we should scroll
            const out = document.getElementById('out');
            if (out && initialLoadDone) {
                const isNearBottom = out.scrollHeight - out.scrollTop - out.clientHeight < 150;
                if (isNearBottom) {
                    scrollToBottom();
                }
            }
        }
    };

    img.addEventListener('load', onLoadOrError);
    img.addEventListener('error', onLoadOrError);
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

    initMediaViewer();
    initFileManager();
    initGroupAvatar();

    MEMBERS_UPDATE_INTERVAL = setInterval(loadMembers, 10000);
    sendOnlineHeartbeat();
    ONLINE_HEARTBEAT_INTERVAL = setInterval(sendOnlineHeartbeat, 20000);

    // Load groups sidebar
    loadGroups();
    setInterval(loadGroups, 60000);
}

// ========== MEDIA VIEWER ==========
function calculateFitToViewZoom(width, height) {
    if (width <= 0 || height <= 0) return 1;

    // Use actual viewport dimensions - much more reliable than trying to measure modal
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;

    // Leave minimal margins for UI elements
    // 50px for side margins, 70px for top/bottom (buttons + caption)
    const effectiveWidth = viewportWidth - 50;
    const effectiveHeight = viewportHeight - 70;

    // Calculate scale to fit while maintaining aspect ratio
    const scaleX = effectiveWidth / width;
    const scaleY = effectiveHeight / height;
    const fitZoom = Math.min(scaleX, scaleY);

    // Return the calculated zoom, ensuring it's at least 0.1x
    // Don't cap at 1x - allow upscaling for small images
    return Math.max(0.1, fitZoom);
}

function openMediaViewer(src, caption, isVideo = false, messageId = null, fileUrl = null) {
    const modal = document.getElementById('media-viewer-modal');
    const container = document.getElementById('viewer-container');
    const captionElem = document.getElementById('viewer-caption');

    if (!modal || !container || !captionElem) return;

    // Store current media info for delete/download buttons
    modal.dataset.messageId = messageId;
    modal.dataset.fileUrl = fileUrl || src;
    modal.dataset.isVideo = isVideo;
    modal.dataset.zoom = '1';
    modal.dataset.baseZoom = '1';
    modal.dataset.panX = '0';
    modal.dataset.panY = '0';

    container.innerHTML = '';

    if (isVideo) {
        const video = document.createElement('video');
        video.src = src;
        video.controls = true;
        video.autoplay = true;
        video.style.maxWidth = 'none';
        video.style.maxHeight = 'none';
        video.style.objectFit = 'contain';
        video.style.display = 'block';
        video.id = 'zoomable-video';
        video.style.transformOrigin = 'center';
        video.style.transition = 'transform 0.2s ease-out';

        // Helper function to apply zoom with proper timing
        const applyVideoZoom = () => {
            const videoWidth = video.videoWidth;
            const videoHeight = video.videoHeight;

            if (videoWidth > 0 && videoHeight > 0) {
                const fitZoom = calculateFitToViewZoom(videoWidth, videoHeight);
                modal.dataset.zoom = fitZoom;
                modal.dataset.baseZoom = fitZoom;

                // Apply initial scaling via CSS properties instead of transform
                const viewportWidth = window.innerWidth - 50;
                const viewportHeight = window.innerHeight - 70;
                const scaledWidth = Math.min(videoWidth * fitZoom, viewportWidth);
                const scaledHeight = Math.min(videoHeight * fitZoom, viewportHeight);

                video.style.width = scaledWidth + 'px';
                video.style.height = scaledHeight + 'px';
                video.style.transform = 'none'; // No transform for base zoom

                return true;
            }
            return false;
        };

        // Try applying zoom after a small delay to allow metadata to load
        const metadataTimeout = setTimeout(() => {
            if (!applyVideoZoom()) {
                // If still no metadata, try again after another delay
                const retryTimeout = setTimeout(() => {
                    applyVideoZoom();
                }, 500);
            }
        }, 100);

        // Also listen for loadedmetadata event
        const handleVideoMetadata = () => {
            clearTimeout(metadataTimeout);
            applyVideoZoom();
        };

        video.addEventListener('loadedmetadata', handleVideoMetadata, { once: true });

        container.appendChild(video);
    } else {
        const img = document.createElement('img');
        img.src = src;
        img.style.maxWidth = 'none';
        img.style.maxHeight = 'none';
        img.style.objectFit = 'contain';
        img.style.cursor = 'grab';
        img.style.transition = 'transform 0.2s ease-out';
        img.id = 'zoomable-img';
        img.style.transformOrigin = 'center';

        // Helper function to apply zoom with proper timing
        const applyImageZoom = () => {
            const imgWidth = img.naturalWidth;
            const imgHeight = img.naturalHeight;

            if (imgWidth > 0 && imgHeight > 0) {
                const fitZoom = calculateFitToViewZoom(imgWidth, imgHeight);
                modal.dataset.zoom = fitZoom;
                modal.dataset.baseZoom = fitZoom;

                // Apply initial scaling via CSS properties instead of transform
                const viewportWidth = window.innerWidth - 50;
                const viewportHeight = window.innerHeight - 70;
                const scaledWidth = Math.min(imgWidth * fitZoom, viewportWidth);
                const scaledHeight = Math.min(imgHeight * fitZoom, viewportHeight);

                img.style.width = scaledWidth + 'px';
                img.style.height = scaledHeight + 'px';
                img.style.transform = 'none'; // No transform for base zoom

                return true;
            }
            return false;
        };

        // Apply zoom immediately if image is already cached
        if (img.complete && img.naturalWidth > 0) {
            applyImageZoom();
        } else {
            // Wait for image to load
            const handleImageLoad = () => {
                applyImageZoom();
                img.removeEventListener('load', handleImageLoad);
            };

            img.addEventListener('load', handleImageLoad);

            // Fallback timeout
            const loadTimeout = setTimeout(() => {
                applyImageZoom();
                img.removeEventListener('load', handleImageLoad);
            }, 1000);

            img.addEventListener('load', () => clearTimeout(loadTimeout));
        }

        container.appendChild(img);
    }

    captionElem.textContent = caption;
    modal.classList.add('active');
}

function initMediaViewer() {
    const closeBtn = document.getElementById('btn-close-viewer');
    const downloadBtn = document.getElementById('btn-download-media');
    const deleteBtn = document.getElementById('btn-delete-media-message');
    const modal = document.getElementById('media-viewer-modal');
    const container = document.getElementById('viewer-container');

    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            modal.classList.remove('active');
            document.getElementById('viewer-container').innerHTML = '';
            modal.dataset.messageId = null;
            modal.dataset.fileUrl = null;
            modal.dataset.zoom = '1';
            modal.dataset.baseZoom = '1';
            modal.dataset.panX = '0';
            modal.dataset.panY = '0';
        });
    }

    if (downloadBtn) {
        downloadBtn.addEventListener('click', () => {
            const fileUrl = modal.dataset.fileUrl;
            if (fileUrl) {
                const a = document.createElement('a');
                a.href = fileUrl;
                // Extract filename from URL
                const urlParts = fileUrl.split('/');
                const filename = urlParts[urlParts.length - 1] || 'download';
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
            }
        });
    }

    if (deleteBtn) {
        deleteBtn.addEventListener('click', () => {
            const messageId = modal.dataset.messageId;
            if (messageId) {
                showDeleteConfirmModal(messageId);
                modal.classList.remove('active');
                document.getElementById('viewer-container').innerHTML = '';
                modal.dataset.messageId = null;
                modal.dataset.zoom = '1';
                modal.dataset.baseZoom = '1';
                modal.dataset.panX = '0';
                modal.dataset.panY = '0';
            }
        });
    }

    // Zoom functionality for images and videos
    if (container) {
        let panX = 0;
        let panY = 0;
        let isPanning = false;
        let panStartX = 0;
        let panStartY = 0;
        let panStartImgX = 0;
        let panStartImgY = 0;

        const getMediaElement = () => {
            return container.querySelector('img') || container.querySelector('video');
        };

        const updateMediaTransform = (zoom, panXVal, panYVal) => {
            const media = getMediaElement();
            if (!media) return;

            const baseZoom = parseFloat(modal.dataset.baseZoom || 1);

            // Only use transform for user zoom (not base zoom)
            if (Math.abs(zoom - baseZoom) < 0.01) {
                // At base zoom level: no transform needed
                media.style.transform = 'none';
            } else {
                // When user zooms beyond base: use transform for zoom delta
                const zoomDelta = zoom / baseZoom;
                media.style.transform = `scale(${zoomDelta}) translate(${panXVal}px, ${panYVal}px)`;
            }
        };

        const updateMediaZoom = (newZoom) => {
            const baseZoom = parseFloat(modal.dataset.baseZoom || 1);
            newZoom = Math.max(baseZoom, Math.min(newZoom, 5)); // Clamp between baseZoom and 5
            modal.dataset.zoom = newZoom;

            // Reset pan when changing zoom (to avoid confusion)
            if (Math.abs(newZoom - baseZoom) < 0.01) {
                panX = 0;
                panY = 0;
            }

            const media = getMediaElement();
            if (media) {
                media.style.cursor = newZoom > baseZoom ? 'grab' : 'default';
                updateMediaTransform(newZoom, panX, panY);
            }
        };

        const updateMediaPosition = (newPanX, newPanY) => {
            const zoom = parseFloat(modal.dataset.zoom || 1);
            const baseZoom = parseFloat(modal.dataset.baseZoom || 1);

            if (zoom <= baseZoom) return; // Only pan when zoomed beyond base

            // Limit pan to reasonable boundaries
            const maxPan = (zoom - baseZoom) * 100;
            panX = Math.max(-maxPan, Math.min(maxPan, newPanX));
            panY = Math.max(-maxPan, Math.min(maxPan, newPanY));

            const media = getMediaElement();
            if (media) {
                media.style.cursor = 'grabbing';
                updateMediaTransform(zoom, panX, panY);
            }
        };

        // Ctrl + Wheel zoom (Desktop)
        container.addEventListener('wheel', (e) => {
            const media = getMediaElement();
            if (!media || modal.dataset.isVideo === 'true') return; // Don't zoom videos

            if (e.ctrlKey || e.metaKey) {
                e.preventDefault();

                let currentZoom = parseFloat(modal.dataset.zoom || 1);
                const baseZoom = parseFloat(modal.dataset.baseZoom || 1);
                const zoomStep = 0.15;

                if (e.deltaY < 0) {
                    currentZoom = Math.min(currentZoom + zoomStep, 5);
                } else {
                    // Allow zoom out to base zoom level, not below
                    currentZoom = Math.max(currentZoom - zoomStep, baseZoom);
                }

                updateMediaZoom(currentZoom);
            }
        }, { passive: false });

        // Double-click to zoom images (not videos)
        container.addEventListener('dblclick', (e) => {
            const media = getMediaElement();
            if (!media || modal.dataset.isVideo === 'true') return;

            let currentZoom = parseFloat(modal.dataset.zoom || 1);
            const baseZoom = parseFloat(modal.dataset.baseZoom || 1);
            const targetZoom = currentZoom === baseZoom ? 2 : baseZoom;

            const startZoom = currentZoom;
            const duration = 300;
            const startTime = Date.now();

            const animateZoom = () => {
                const elapsed = Date.now() - startTime;
                const progress = Math.min(elapsed / duration, 1);

                const easeProgress = progress < 0.5
                    ? 2 * progress * progress
                    : -1 + (4 - 2 * progress) * progress;

                const newZoom = startZoom + (targetZoom - startZoom) * easeProgress;
                updateMediaZoom(newZoom);

                if (progress < 1) {
                    requestAnimationFrame(animateZoom);
                }
            };

            animateZoom();
        });

        // Touch pinch zoom (Mobile, images only)
        let lastDistance = 0;

        modal.addEventListener('touchstart', (e) => {
            if (e.touches.length === 2 && modal.dataset.isVideo !== 'true') {
                const touch1 = e.touches[0];
                const touch2 = e.touches[1];
                lastDistance = Math.hypot(
                    touch2.clientX - touch1.clientX,
                    touch2.clientY - touch1.clientY
                );
            }
        });

        modal.addEventListener('touchmove', (e) => {
            if (e.touches.length !== 2 || modal.dataset.isVideo === 'true') return;

            const media = getMediaElement();
            if (!media) return;

            e.preventDefault();

            const touch1 = e.touches[0];
            const touch2 = e.touches[1];
            const currentDistance = Math.hypot(
                touch2.clientX - touch1.clientX,
                touch2.clientY - touch1.clientY
            );

            if (lastDistance > 0) {
                let zoom = parseFloat(modal.dataset.zoom || 1);
                const distanceDelta = currentDistance - lastDistance;
                const zoomDelta = distanceDelta * 0.01;
                zoom = Math.max(1, Math.min(zoom + zoomDelta, 5));

                updateMediaZoom(zoom);
            }

            lastDistance = currentDistance;
        }, { passive: false });

        // Mouse drag for pan when zoomed (images only)
        container.addEventListener('mousedown', (e) => {
            const media = getMediaElement();
            if (!media || modal.dataset.isVideo === 'true') return;

            const zoom = parseFloat(modal.dataset.zoom || 1);
            const baseZoom = parseFloat(modal.dataset.baseZoom || 1);

            if (zoom <= baseZoom) return;

            e.preventDefault();
            isPanning = true;
            panStartX = e.clientX;
            panStartY = e.clientY;
            panStartImgX = panX;
            panStartImgY = panY;

            if (media) media.style.cursor = 'grabbing';
        });

        document.addEventListener('mousemove', (e) => {
            if (!isPanning || !modal.classList.contains('active')) return;

            const media = getMediaElement();
            if (!media || modal.dataset.isVideo === 'true') return;

            const deltaX = (e.clientX - panStartX) * 0.7;
            const deltaY = (e.clientY - panStartY) * 0.7;

            updateMediaPosition(panStartImgX + deltaX, panStartImgY + deltaY);
        });

        document.addEventListener('mouseup', () => {
            if (isPanning) {
                isPanning = false;
                const media = getMediaElement();
                const zoom = parseFloat(modal.dataset.zoom || 1);
                const baseZoom = parseFloat(modal.dataset.baseZoom || 1);

                if (media && zoom > baseZoom && modal.dataset.isVideo !== 'true') {
                    media.style.cursor = 'grab';
                }
            }
        });

        // Single touch drag for mobile pan
        let touchPanStartX = 0;
        let touchPanStartY = 0;

        modal.addEventListener('touchstart', (e) => {
            if (e.touches.length === 1 && modal.dataset.isVideo !== 'true') {
                const media = getMediaElement();
                const zoom = parseFloat(modal.dataset.zoom || 1);
                const baseZoom = parseFloat(modal.dataset.baseZoom || 1);

                if (zoom > baseZoom && media) {
                    touchPanStartX = e.touches[0].clientX;
                    touchPanStartY = e.touches[0].clientY;
                    isPanning = true;
                    panStartImgX = panX;
                    panStartImgY = panY;
                }
            }
        });

        modal.addEventListener('touchmove', (e) => {
            if (!isPanning || e.touches.length !== 1 || modal.dataset.isVideo === 'true') return;

            const media = getMediaElement();
            if (!media) return;

            e.preventDefault();

            const deltaX = (e.touches[0].clientX - touchPanStartX) * 0.7;
            const deltaY = (e.touches[0].clientY - touchPanStartY) * 0.7;

            updateMediaPosition(panStartImgX + deltaX, panStartImgY + deltaY);
        }, { passive: false });

        modal.addEventListener('touchend', (e) => {
            if (e.touches.length === 0) {
                isPanning = false;
            }
        });
    }
}

// ========== FILE MANAGER ==========
let fmStream = null;
let fmRecorder = null;
let fmChunks = [];
let fmPickedFiles = [];
let fmSelectedIndices = new Set();
let fmCameraFacing = 'user'; // 'user' for front, 'environment' for back

function initFileManager() {
    const fmModal = document.getElementById('file-manager-modal');
    if (!fmModal) return;

    const fmVideoPreview = document.getElementById('fm-video-preview');
    const fmGalleryGrid = document.getElementById('fm-gallery-grid');
    const fmEmptyGallery = document.getElementById('fm-empty-gallery');
    const btnFmSend = document.getElementById('btn-fm-send');
    const fmTitle = fmModal.querySelector('.fm-title');

    // Tab switching
    const tabs = fmModal.querySelectorAll('.fm-tab-btn');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const view = tab.dataset.view;
            if (view === 'gallery' || view === 'files') {
                switchFmView(view);
            }
        });
    });

    function switchFmView(view) {
        fmModal.querySelectorAll('.fm-view').forEach(v => v.classList.remove('active'));
        fmModal.querySelectorAll('.fm-tab-btn').forEach(t => t.classList.remove('active'));

        const targetView = document.getElementById(`fm-${view}-view`);
        const targetTab = fmModal.querySelector(`.fm-tab-btn[data-view="${view}"]`);

        if (targetView) targetView.classList.add('active');
        if (targetTab) targetTab.classList.add('active');

        if (fmTitle) fmTitle.textContent = view.charAt(0).toUpperCase() + view.slice(1);

        updateSendButton();
    }

    function updateSendButton() {
        if (fmSelectedIndices.size > 0) {
            btnFmSend.style.display = 'block';
            btnFmSend.textContent = `Send ${fmSelectedIndices.size}`;
        } else {
            btnFmSend.style.display = 'none';
        }
    }

    // Gallery Logic
    const btnOpenGallery = document.getElementById('btn-fm-open-gallery');
    const galleryInput = document.createElement('input');
    galleryInput.type = 'file';
    galleryInput.multiple = true;
    galleryInput.accept = 'image/*,video/*';

    if (btnOpenGallery) {
        btnOpenGallery.addEventListener('click', () => galleryInput.click());
    }

    const btnCameraDirect = document.getElementById('btn-fm-camera-direct');
    if (btnCameraDirect) {
        btnCameraDirect.addEventListener('click', () => startFmCamera(true));
    }

    galleryInput.addEventListener('change', (e) => {
        const files = Array.from(e.target.files);
        if (files.length > 0) {
            addFilesToGallery(files);
        }
    });

    function addFilesToGallery(files) {
        files.forEach(file => {
            fmPickedFiles.push(file);
            fmSelectedIndices.add(fmPickedFiles.length - 1);
        });
        renderGallery();
        updateSendButton();
    }

    function renderGallery() {
        if (!fmGalleryGrid) return;

        fmGalleryGrid.innerHTML = `
            <div class="fm-grid-item fm-camera-slot" id="btn-fm-camera-direct">
              <span class="fm-icon">📷</span>
              <span>Photo</span>
            </div>
            <div class="fm-grid-item fm-camera-slot" id="btn-fm-video-direct">
              <span class="fm-icon">🎥</span>
              <span>Video</span>
            </div>
        `;

        // Re-attach camera listeners
        const btnCameraDirect = document.getElementById('btn-fm-camera-direct');
        if (btnCameraDirect) {
            btnCameraDirect.addEventListener('click', () => startFmCamera(true));
        }

        const btnVideoDirect = document.getElementById('btn-fm-video-direct');
        if (btnVideoDirect) {
            btnVideoDirect.addEventListener('click', () => startFmCamera(false));
        }

        if (fmPickedFiles.length === 0) {
            if (fmEmptyGallery) fmEmptyGallery.style.display = 'flex';
        } else {
            if (fmEmptyGallery) fmEmptyGallery.style.display = 'none';
            fmPickedFiles.forEach((file, index) => {
                const item = document.createElement('div');
                item.className = 'fm-grid-item';
                if (fmSelectedIndices.has(index)) item.classList.add('selected');

                const isVideo = file.type.startsWith('video/');
                if (isVideo) {
                    const video = document.createElement('video');
                    video.src = URL.createObjectURL(file);
                    video.muted = true;
                    video.addEventListener('loadedmetadata', () => {
                        video.currentTime = 0.1;
                    });
                    item.appendChild(video);

                    const badge = document.createElement('div');
                    badge.className = 'fm-video-badge';
                    badge.innerHTML = '<span>▶</span>';
                    item.appendChild(badge);
                } else {
                    const img = document.createElement('img');
                    img.src = URL.createObjectURL(file);
                    item.appendChild(img);
                }

                const circle = document.createElement('div');
                circle.className = 'fm-selection-circle';
                item.appendChild(circle);

                item.addEventListener('click', () => {
                    if (fmSelectedIndices.has(index)) {
                        fmSelectedIndices.delete(index);
                        item.classList.remove('selected');
                    } else {
                        fmSelectedIndices.add(index);
                        item.classList.add('selected');
                    }
                    updateSendButton();
                });

                fmGalleryGrid.appendChild(item);
            });
        }
    }

    // Send logic
    if (btnFmSend) {
        btnFmSend.addEventListener('click', () => {
            const selectedFilesList = Array.from(fmSelectedIndices).map(i => fmPickedFiles[i]);
            if (selectedFilesList.length > 0) {
                addFilesToSelection(selectedFilesList);
                fmModal.classList.remove('active');
                // Reset
                fmPickedFiles = [];
                fmSelectedIndices.clear();
                renderGallery();
            }
        });
    }

    // System Files
    const btnSystemDirect = document.getElementById('btn-fm-system-direct');
    if (btnSystemDirect) {
        btnSystemDirect.addEventListener('click', () => {
            document.getElementById('file-input').click();
            fmModal.classList.remove('active');
        });
    }

    const btnFm = document.getElementById('btn-file-manager');
    if (btnFm) {
        btnFm.addEventListener('click', () => {
            fmModal.classList.add('active');
            renderGallery();
        });
    }

    const btnCloseFm = document.getElementById('btn-close-fm');
    if (btnCloseFm) {
        btnCloseFm.addEventListener('click', () => {
            stopFmCamera();
            fmModal.classList.remove('active');
        });
    }

    const btnFmCapture = document.getElementById('btn-fm-capture');
    if (btnFmCapture) {
        btnFmCapture.addEventListener('click', async () => {
            if (!fmStream) return;
            const isVideo = fmStream.getAudioTracks().length > 0;
            if (isVideo) {
                if (fmRecorder && fmRecorder.state === 'recording') {
                    fmRecorder.stop();
                    btnFmCapture.classList.remove('recording');
                } else {
                    fmChunks = [];
                    fmRecorder = new MediaRecorder(fmStream);
                    fmRecorder.ondataavailable = (e) => fmChunks.push(e.data);
                    fmRecorder.onstop = () => {
                        const blob = new Blob(fmChunks, { type: 'video/webm' });
                        const file = new File([blob], `video_${Date.now()}.webm`, { type: 'video/webm' });
                        addFilesToGallery([file]);
                        stopFmCamera();
                        switchFmView('gallery');
                    };
                    fmRecorder.start();
                    btnFmCapture.classList.add('recording');
                }
            } else {
                const canvas = document.createElement('canvas');
                canvas.width = fmVideoPreview.videoWidth;
                canvas.height = fmVideoPreview.videoHeight;
                canvas.getContext('2d').drawImage(fmVideoPreview, 0, 0);
                canvas.toBlob((blob) => {
                    const file = new File([blob], `photo_${Date.now()}.jpg`, { type: 'image/jpeg' });
                    addFilesToGallery([file]);
                    stopFmCamera();
                    switchFmView('gallery');
                }, 'image/jpeg', 0.9);
            }
        });
    }

    const btnFmStop = document.getElementById('btn-fm-stop');
    if (btnFmStop) btnFmStop.addEventListener('click', stopFmCamera);

    const btnFmToggleCamera = document.getElementById('btn-fm-toggle-camera');
    if (btnFmToggleCamera) btnFmToggleCamera.addEventListener('click', toggleFmCamera);

    async function startFmCamera(videoOnly = false) {
        try {
            fmStream = await navigator.mediaDevices.getUserMedia({
                video: { facingMode: fmCameraFacing },
                audio: !videoOnly
            });
            fmVideoPreview.srcObject = fmStream;
            switchFmView('camera');
        } catch (err) {
            alert('Camera access denied or not available');
        }
    }

    function stopFmCamera() {
        if (fmStream) {
            fmStream.getTracks().forEach(track => track.stop());
            fmStream = null;
        }
        // Reset camera facing to default when stopping
        fmCameraFacing = 'user';
        switchFmView('gallery');
    }

    async function toggleFmCamera() {
        // Check if it's a mobile device
        const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);

        if (!isMobile) {
            // PC doesn't support camera switching
            return;
        }

        if (!fmStream) return;

        // Stop current stream
        fmStream.getTracks().forEach(track => track.stop());

        // Toggle camera
        fmCameraFacing = fmCameraFacing === 'user' ? 'environment' : 'user';

        try {
            fmStream = await navigator.mediaDevices.getUserMedia({
                video: { facingMode: fmCameraFacing },
                audio: fmStream.getAudioTracks().length > 0
            });
            fmVideoPreview.srcObject = fmStream;
        } catch (err) {
            // If camera switch fails, switch back
            fmCameraFacing = fmCameraFacing === 'user' ? 'environment' : 'user';
            alert('Camera switch failed. Device may not support back camera.');
        }
    }

    function addFilesToSelection(newFiles) {
        const dt = new DataTransfer();
        for (let i = 0; i < selectedFiles.length; i++) dt.items.add(selectedFiles[i]);
        for (let i = 0; i < newFiles.length; i++) dt.items.add(newFiles[i]);
        processFileUpload(dt.files);
    }
}

// ========== GROUP AVATAR ==========
function initGroupAvatar() {
    const groupAvatarInput = document.getElementById('group-avatar-input');
    const groupAvatarPreview = document.getElementById('group-avatar-preview');
    if (!groupAvatarInput || !groupAvatarPreview) return;

    groupAvatarInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const formData = new FormData();
        formData.append('file', file);
        fetch(`/api/groups/${GROUP_ID}/avatar`, {
            method: 'POST',
            body: formData,
            credentials: 'include'
        })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    const url = `/group/avatar/${GROUP_ID}?t=${Date.now()}`;
                    groupAvatarPreview.src = url;
                    const headerAvatar = document.getElementById('header-group-avatar');
                    if (headerAvatar) headerAvatar.src = url;
                } else {
                    alert(data.error || 'Failed to upload avatar');
                }
            })
            .catch(err => alert('Upload failed'));
    });

    groupAvatarPreview.parentElement.addEventListener('click', () => {
        groupAvatarInput.click();
    });
}

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
        } else { // Group avatar
            avatarHtml = `<img src="/group/avatar/${group.id}" alt="Group Avatar" style="width: 32px; height: 32px; border-radius: 50%; margin-right: 8px; object-fit: cover; flex-shrink: 0;">`;
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

            // Hide delete confirmation modal
            const modal = document.getElementById('confirm-modal');
            if (modal) {
                modal.classList.remove('active');
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

    // Robust Nonce and URL extraction
    let content = rest;
    let urls = {};
    let nonce = null;

    // Nonce can be anywhere after content, usually at the end
    const nonceMatch = content.match(/\|NONCE:([^\s|]+)/);
    if (nonceMatch) {
        nonce = nonceMatch[1];
        content = content.replace(nonceMatch[0], '');
    }

    const urlsMatch = content.match(/\|URLS:(\{.*\})/);
    if (urlsMatch) {
        try {
            urls = JSON.parse(urlsMatch[1]);
            content = content.replace(urlsMatch[0], '');
        } catch (e) {
            console.warn('[Parse] Failed to parse URLs JSON:', e);
        }
    }

    return { id: messageId, timestamp, username, content: content.trim(), urls, nonce };
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
        img.addEventListener('click', (e) => {
            e.stopPropagation();
            window.open(url, '_blank');
        });
        card.appendChild(img);
    }

    card.addEventListener('click', () => window.open(url, '_blank'));
    return card;
}

function createMessageElement(data, messageId) {
    const parsed = parseMessageData(data);
    if (!parsed) return null;

    // If this is a system-style message (we use username == 'SYSTEM') render inline and italic
    if (parsed.username === 'SYSTEM') {
        const sysWrap = document.createElement('div');
        sysWrap.className = 'message system-inline';
        sysWrap.setAttribute('data-message-id', messageId);

        const contentWrapper = document.createElement('div');
        contentWrapper.className = 'message-content-wrapper';

        const mainContent = document.createElement('div');
        mainContent.className = 'message-content system-inline-content';
        mainContent.style.fontStyle = 'italic';
        mainContent.style.color = '#333';
        mainContent.style.background = 'transparent';
        mainContent.style.padding = '6px 4px';
        mainContent.style.margin = '6px 0';
        mainContent.textContent = parsed.content;

        contentWrapper.appendChild(mainContent);
        sysWrap.appendChild(contentWrapper);
        return sysWrap;
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
        avatarImg.onerror = function () {
            this.src = '/static/unknown_user_phasma_icon.png';
        };
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
    header.innerHTML = `<strong class="msg-sender">${escapeHtml(parsed.username)}</strong> <span class="msg-time">${localDate}, ${localTime}</span>`;
    contentWrapper.appendChild(header);

    const mainContent = document.createElement("div");
    mainContent.className = "message-content";

    // Parse text spoilers: [spoiler]text[spoiler], [spoiler]text[], or ||text||
    const spoilerRegex = /\[spoiler\]([\s\S]*?)(?:\[spoiler\]|\[\])|\|\|([\s\S]*?)\|\|/gi;
    let content = (parsed.content || "").trim();

    let mediaHandled = false;

    // Robust parsing for [TYPE:ID:FILENAME:URL] or [TYPE:ID:URL]
    if (content.startsWith("[") && content.endsWith("]")) {
        const inner = content.slice(1, -1);
        const parts = inner.split(':');
        const type = parts[0];

        if (['PHOTO', 'VIDEO', 'AUDIO', 'FILE'].includes(type)) {
            mediaHandled = true;
            let fileId, fileName, fileUrl;

            if (type === 'FILE') {
                // [FILE:ID:CATEGORY:FILENAME:URL]
                fileId = parts[1];
                const category = parts[2];
                fileName = parts[3];
                fileUrl = parts.slice(4).join(':');

                const fileDiv = document.createElement("div");
                fileDiv.className = "file-msg";
                const fileAttachment = document.createElement("div");
                fileAttachment.className = "file-attachment";

                const fileIcon = document.createElement("img");
                fileIcon.className = "file-icon";
                fileIcon.src = "/static/phasma_file.png";
                const fileInfo = document.createElement("div");
                fileInfo.className = "file-info";
                const fileNameElem = document.createElement("div");
                fileNameElem.className = "file-name";

                const isSpoiler = fileName.startsWith('SPOILER_');
                let displayFileName = fileName;
                if (isSpoiler) {
                    displayFileName = "SPOILER: " + fileName.replace('SPOILER_', '');
                    fileDiv.classList.add("spoiler");
                    fileDiv.addEventListener('click', () => fileDiv.classList.toggle('revealed'));
                }
                fileNameElem.textContent = displayFileName;
                fileInfo.appendChild(fileNameElem);

                const downloadBtn = document.createElement("button");
                downloadBtn.className = "file-download-btn";
                downloadBtn.textContent = "⬇";
                downloadBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const a = document.createElement('a');
                    a.href = fileUrl;
                    a.download = fileName;
                    a.click();
                });

                fileAttachment.appendChild(fileIcon);
                fileAttachment.appendChild(fileInfo);
                fileAttachment.appendChild(downloadBtn);
                fileDiv.appendChild(fileAttachment);
                mainContent.appendChild(fileDiv);
            } else {
                // PHOTO, VIDEO, AUDIO
                fileId = parts[1];
                if (parts.length >= 4) {
                    fileName = parts[2];
                    fileUrl = parts.slice(3).join(':');
                } else {
                    fileName = "";
                    fileUrl = parts.slice(2).join(':');
                }

                const isSpoiler = fileName.startsWith('SPOILER_');

                if (type === 'PHOTO') {
                    const imgContainer = document.createElement("div");
                    imgContainer.style.position = "relative";
                    imgContainer.style.display = "inline-block";

                    // Loading container
                    const loadingContainer = document.createElement("div");
                    loadingContainer.className = "image-loading-container";

                    // Spinner
                    const spinner = document.createElement("div");
                    spinner.className = "image-spinner";
                    loadingContainer.appendChild(spinner);

                    const img = document.createElement("img");
                    img.className = "msg-photo loading";
                    img.loading = "lazy";

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
                        loadingContainer.innerHTML = '<span style="color: #ff4b4b; font-size: 12px; padding: 10px; display:block; text-align: center;">⚠️ Failed to load image</span>';
                    };

                    if (isSpoiler) {
                        img.classList.add("spoiler-media");
                        // Click to reveal spoiler
                        img.addEventListener('click', () => img.classList.toggle('revealed'));

                        const overlay = document.createElement("div");
                        overlay.className = "spoiler-overlay";
                        overlay.innerText = "SPOILER";

                        loadingContainer.appendChild(img);
                        imgContainer.appendChild(loadingContainer);
                        imgContainer.appendChild(overlay);
                    } else {
                        img.addEventListener('click', () => openMediaViewer(fileUrl, `Photo from ${parsed.username}`, false, parsed.id, fileUrl));
                        loadingContainer.appendChild(img);
                        imgContainer.appendChild(loadingContainer);
                    }
                    // Register image loading for scroll tracking
                    registerImageLoad(messageId, img);
                    img.src = fileUrl;
                    mainContent.appendChild(imgContainer);
                } else if (type === 'VIDEO') {
                    const videoDiv = document.createElement("div");
                    videoDiv.className = "video-msg";
                    videoDiv.style.position = "relative";

                    const video = document.createElement("video");
                    video.className = "video-player";
                    if (isSpoiler) {
                        video.classList.add("spoiler-media");
                        video.controls = false; // Disable controls until revealed

                        // Ensure video is appended BEFORE overlay for CSS selector (+)
                        videoDiv.appendChild(video);

                        const overlay = document.createElement("div");
                        overlay.className = "spoiler-overlay";
                        overlay.innerText = "SPOILER";
                        videoDiv.appendChild(overlay);

                        // Attach listener to videoDiv (wrapper) because native controls can intercept clicks
                        videoDiv.addEventListener('click', (e) => {
                            e.stopPropagation();
                            if (!video.classList.contains('revealed')) {
                                video.classList.add('revealed');
                                video.controls = true;
                                e.preventDefault();
                            } else {
                                // If already revealed, open media viewer
                                openMediaViewer(fileUrl, `Video from ${parsed.username}`, true, parsed.id, fileUrl);
                            }
                        });
                    } else {
                        video.addEventListener('click', (e) => {
                            openMediaViewer(fileUrl, `Video from ${parsed.username}`, true, parsed.id, fileUrl);
                            e.preventDefault();
                        });
                        videoDiv.appendChild(video);
                    }
                    video.muted = true;
                    video.setAttribute('playsinline', '');
                    video.preload = 'metadata';

                    video.addEventListener('loadeddata', () => { video.currentTime = 0.1; }, { once: true });
                    video.addEventListener('seeked', () => {
                        try {
                            const canvas = document.createElement('canvas');
                            canvas.width = video.videoWidth;
                            canvas.height = video.videoHeight;
                            const ctx = canvas.getContext('2d');
                            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                            video.poster = canvas.toDataURL('image/jpeg', 0.7);
                        } catch (e) {
                            console.warn('[Video] Failed to generate thumbnail:', e);
                        }
                    }, { once: true });

                    video.src = fileUrl;
                    mainContent.appendChild(videoDiv);
                } else if (type === 'AUDIO') {
                    const audioDiv = document.createElement("div");
                    audioDiv.className = "audio-msg";
                    if (isSpoiler) {
                        audioDiv.classList.add("spoiler");
                        audioDiv.addEventListener('click', () => audioDiv.classList.toggle('revealed'));
                    }
                    const audio = document.createElement("audio");
                    audio.controls = true;
                    audio.src = fileUrl;
                    audioDiv.appendChild(audio);
                    mainContent.appendChild(audioDiv);
                }
            }
        }
    }

    if (!mediaHandled) {
        const textDiv = document.createElement("div");
        textDiv.className = "message-text";

        // Check if content is a URL
        const urlRegex = /^(https?:\/\/[^\s]+)$/;
        if (urlRegex.test(content)) {
            const link = document.createElement("a");
            link.href = content;
            link.textContent = content;
            link.target = "_blank";
            link.style.color = "#0078d4";
            link.style.textDecoration = "underline";
            link.addEventListener('click', (e) => e.stopPropagation());
            textDiv.appendChild(link);

            if (parsed.urls && parsed.urls[content]) {
                textDiv.style.display = 'none';
            }
        } else {
            // Apply text spoilers - Safe approach with proper escaping
            const escaped = escapeHtml(content);

            // Build HTML carefully - first escape, then replace spoilers with safe placeholders
            let html = escaped;
            const spoilerMap = new Map();
            let spoilerIndex = 0;

            // Replace all spoiler markers with placeholders
            html = html.replace(spoilerRegex, (match, p1, p2) => {
                const text = p1 || p2;
                const placeholder = `<!--SPOILER_${spoilerIndex}-->`;
                spoilerMap.set(spoilerIndex, text);
                spoilerIndex++;
                return placeholder;
            });

            // Now safely set innerHTML with only placeholders
            textDiv.innerHTML = html;

            // Replace placeholders with actual spoiler elements
            const walker = document.createTreeWalker(
                textDiv,
                NodeFilter.SHOW_COMMENT,
                null,
                false
            );

            let comment;
            while (comment = walker.nextNode()) {
                const match = comment.nodeValue.match(/^SPOILER_(\d+)$/);
                if (match) {
                    const idx = parseInt(match[1], 10);
                    const spoilerText = spoilerMap.get(idx);

                    const spoiler = document.createElement('span');
                    spoiler.className = 'spoiler';
                    spoiler.textContent = spoilerText;
                    spoiler.addEventListener('click', (e) => {
                        e.stopPropagation();
                        spoiler.classList.toggle('revealed');
                    });

                    comment.parentNode.replaceChild(spoiler, comment);
                }
            }
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
    msgWrapper.classList.add(isOwnMessage ? 'my-msg' : 'other-msg');

    if (isOwnMessage) {
        const deleteBtn = document.createElement("button");
        deleteBtn.className = "message-delete-btn";
        deleteBtn.textContent = "🗑️ delete";
        deleteBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            showDeleteConfirmModal(messageId);
        });
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
                    // Wait for all images to load before final scroll
                    // Check every 50ms if images are still loading
                    const checkImagesLoaded = setInterval(() => {
                        if (loadingImages.size === 0) {
                            clearInterval(checkImagesLoaded);
                            scrollContainer.scrollTop = scrollContainer.scrollHeight;
                        }
                    }, 50);
                    // Timeout after 5 seconds to prevent infinite waiting
                    setTimeout(() => clearInterval(checkImagesLoaded), 5000);
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
                        if (!data || data === '{}' || data.startsWith('{"type": "ping"')) return;

                        // Unescape newlines that were escaped during SSE transmission
                        const unescapedData = data.replace(/\\n/g, '\n').replace(/\\r/g, '\r');

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
                        const parsed = parseMessageData(unescapedData);
                        if (!parsed) return; // Skip if parsing failed (e.g. ping)

                        const msgId = parsed.id;
                        const msgNonce = parsed.nonce; // We need to update parseMessageData to extract this

                        // Check if message already exists (deduplication)
                        // Check by ID OR by Nonce
                        let existing = document.querySelector(`[data-message-id="${msgId}"]`);
                        if (!existing && msgNonce) {
                            existing = document.querySelector(`[data-nonce="${msgNonce}"]`);
                        }

                        if (existing) {
                            // If it exists and was "sending", update it
                            if (existing.classList.contains('sending')) {
                                existing.classList.remove('sending');
                                existing.style.opacity = '1';
                                existing.setAttribute('data-message-id', msgId); // Ensure ID is correct
                                // Keep nonce for fallback checking
                            }
                            // Message already exists, skip adding it again
                            return;
                        }

                        const msgElement = createMessageElement(unescapedData, msgId);
                        if (msgElement) {
                            // Add nonce as fallback identifier
                            if (msgNonce) {
                                msgElement.setAttribute('data-nonce', msgNonce);
                            }
                            messagesContainer.appendChild(msgElement);
                        }

                        // Play notification sound if message is not from current user and window is not focused
                        if (parsed && parsed.username !== CURRENT_USER) {
                            if (isWindowActive) {
                                markAsRead();
                            } else {
                                const audio = new Audio('/static/phasma_notification_sound.mp3');
                                audio.play().catch(e => console.log('Audio play failed:', e));
                            }
                        }

                        // Always scroll to bottom if message is from current user
                        // Otherwise scroll only if user is already near bottom (to prevent interrupting reading old messages)
                        if (parsed && parsed.username === CURRENT_USER) {
                            scrollToBottom();
                        } else {
                            const isNearBottom = out.scrollHeight - out.scrollTop - out.clientHeight < 150;
                            if (isNearBottom) {
                                scrollToBottom();
                            }
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
function scrollToBottom() {
    const out = document.getElementById('out');
    requestAnimationFrame(() => {
        out.scrollTop = out.scrollHeight;
    });
}

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

    const textInput = document.getElementById('in');
    const text = textInput.value;
    if (!text.trim()) return;

    // Optimistic UI
    const tempId = Date.now();
    const nonce = `nonce_${tempId}_${Math.random().toString(36).substr(2, 9)}`;
    const timestamp = Math.floor(Date.now() / 1000);
    const optimisticData = `[ID:${tempId}][${timestamp}] ${CURRENT_USER}: ${text}`;

    const msgElement = createMessageElement(optimisticData, tempId);
    if (msgElement) {
        msgElement.classList.add('sending');
        msgElement.setAttribute('data-nonce', nonce); // Store nonce
        msgElement.style.opacity = '0.7';
        messagesContainer.appendChild(msgElement);
        scrollToBottom();
    }

    textInput.value = '';
    isSendingMessage = true;

    fetch(`/group/${GROUP_ID}/post`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${GROUP_SESSION_TOKEN}`,
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ message: text, nonce: nonce }) // Send nonce
    })
        .then(async response => {
            if (!response.ok) {
                if (response.status === 429) throw new Error('You are sending requests too quickly.');
                if (response.status === 401) {
                    handleSessionExpired();
                    throw new Error('Session expired');
                }
                throw new Error('Failed to send message');
            }

            // Success - update ID if returned
            try {
                const data = await response.json();
                if (data.message_id && msgElement) {
                    msgElement.setAttribute('data-message-id', data.message_id);
                    // Also update our map if we use it
                    messageIdToElementMap.set(data.message_id, msgElement);
                }
            } catch (e) {
                // Ignore JSON parse error if 204 or empty
            }

            if (msgElement) {
                msgElement.classList.remove('sending');
                msgElement.style.opacity = '1';
            }
        })
        .catch(err => {
            console.error(err);
            if (msgElement) {
                msgElement.classList.add('error');
                msgElement.style.borderLeft = '3px solid red';
                showError(err.message || 'Failed to send message');
            }
            // Restore input if needed, but maybe annoying if they typed more
        })
        .finally(() => {
            isSendingMessage = false;
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
    const uploadSingle = async (file) => {
        const formData = new FormData();
        formData.append('file', file);

        const response = await fetch(`/group/${GROUP_ID}/upload`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${GROUP_SESSION_TOKEN}` },
            body: formData
        });

        if (!response.ok) {
            let errMsg = 'Unknown error';
            try {
                const resp = await response.json();
                errMsg = resp.message || resp.error || errMsg;
            } catch (e) { }
            throw new Error(errMsg);
        }
        return response.json();
    };

    for (let i = 0; i < selectedFiles.length; i++) {
        let file = selectedFiles[i];

        // Check if spoiler is active for this file
        const previewItem = document.querySelector(`.preview-item[data-index="${i}"]`);
        const isSpoiler = previewItem && previewItem.querySelector('.btn-spoiler-toggle.active');

        if (isSpoiler && !file.name.startsWith('SPOILER_')) {
            // Create a new file object with SPOILER_ prefix
            const blob = file.slice(0, file.size, file.type);
            file = new File([blob], 'SPOILER_' + file.name, { type: file.type });
        }

        try {
            await uploadSingle(file);
            uploadedCount++;
        } catch (e) {
            console.error(`Failed to upload ${file.name}`, e);
            errorCount++;
            showError(`✗ Failed to upload ${file.name}: ${e.message}`);
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

    selectedFiles.forEach((file, index) => {
        const item = document.createElement('div');
        item.className = 'preview-item';
        item.setAttribute('data-index', index);

        // Spoiler toggle button (eye icon)
        const spoilerBtn = document.createElement('button');
        spoilerBtn.className = 'btn-spoiler-toggle';
        spoilerBtn.innerHTML = '👁️';
        spoilerBtn.title = 'Toggle Spoiler';
        spoilerBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            spoilerBtn.classList.toggle('active');
            // We'll handle the SPOILER_ prefix during upload
        });
        item.appendChild(spoilerBtn);

        // Remove button
        const removeBtn = document.createElement('button');
        removeBtn.className = 'preview-remove-btn';
        removeBtn.innerHTML = '✕';
        removeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            removeFile(index);
        });
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
            video.controls = true;
            video.muted = true;
            video.setAttribute('playsinline', '');
            video.preload = 'metadata';
            video.style.maxWidth = '100%';
            video.style.maxHeight = '200px';

            // Generate thumbnail using canvas for preview
            video.addEventListener('loadeddata', () => {
                video.currentTime = 0.1;
            }, { once: true });

            video.addEventListener('seeked', () => {
                try {
                    const canvas = document.createElement('canvas');
                    canvas.width = video.videoWidth;
                    canvas.height = video.videoHeight;
                    const ctx = canvas.getContext('2d');
                    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                    video.poster = canvas.toDataURL('image/jpeg', 0.7);
                } catch (e) {
                    console.warn('[Preview] Failed to generate thumbnail:', e);
                }
            }, { once: true });

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
        console.log('Push subscription created');

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

    const eventSource = new EventSource("/api/user/events", { withCredentials: true });

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
    // Inline subtle system message (used for join/leave and small hints)
    const msg = document.createElement("div");
    msg.className = "message system-inline";
    const contentWrapper = document.createElement('div');
    contentWrapper.className = 'message-content-wrapper';
    const mainContent = document.createElement('div');
    mainContent.className = 'message-content system-inline-content';
    mainContent.style.fontStyle = 'italic';
    mainContent.style.color = '#333';
    mainContent.style.fontSize = '0.9em';
    mainContent.style.margin = '6px 0';
    mainContent.textContent = text;
    contentWrapper.appendChild(mainContent);
    msg.appendChild(contentWrapper);
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
