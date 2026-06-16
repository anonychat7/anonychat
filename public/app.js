(() => {
  const screens = {
    login: document.getElementById('screen-login'),
    about: document.getElementById('screen-about'),
    searching: document.getElementById('screen-searching'),
    chat: document.getElementById('screen-chat'),
  };

  function showScreen(name) {
    Object.values(screens).forEach(s => s.classList.remove('active'));
    screens[name].classList.add('active');
  }

  const themeToggle = document.getElementById('theme-toggle');
  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    themeToggle.textContent = theme === 'light' ? '◑' : '◐';
    try { localStorage.setItem('anonychat-theme', theme); } catch {}
  }
  let savedTheme = 'dark';
  try { savedTheme = localStorage.getItem('anonychat-theme') || 'dark'; } catch {}
  applyTheme(savedTheme);
  themeToggle.addEventListener('click', () => {
    const next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    applyTheme(next);
  });

  document.querySelectorAll('.mode-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.mode-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.mode-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('mode-' + tab.dataset.mode).classList.add('active');
    });
  });

  document.getElementById('about-btn').addEventListener('click', () => {
    showScreen('about');
    checkConn();
  });
  document.getElementById('about-back').addEventListener('click', () => showScreen('login'));

  function checkConn() {
    const el = document.getElementById('conn-status');
    fetch('/').then(() => { el.textContent = 'server is online'; })
      .catch(() => { el.textContent = 'server unreachable'; });
  }

  function getSessionId() {
    try { return localStorage.getItem('anonychat-session') || null; } catch { return null; }
  }
  function setSessionId(id) {
    try { localStorage.setItem('anonychat-session', id); } catch {}
  }
  function clearSessionId() {
    try { localStorage.removeItem('anonychat-session'); } catch {}
  }

  let socket = null;
  let myNickname = '';
  let pendingImage = null;
  let typingTimeout = null;
  let currentMode = 'room';
  let socketReady = false;

  function initSocket(cb) {
    if (socket && socketReady) { if (cb) cb(); return; }
    if (socket) { if (cb) socket.once('session-ready', cb); return; }

    socket = io({ transports: ['websocket', 'polling'] });

    socket.on('connect', () => {
      socket.emit('resume-session', getSessionId());
    });

    socket.on('session', ({ sessionId }) => {
      setSessionId(sessionId);
      socketReady = true;
      socket.emit('session-ready');
      if (cb) { cb(); cb = null; }
    });

    socket.on('joined', (data) => {
      socketReady = true;
      myNickname = data.nickname;
      currentMode = data.mode;
      const roomLabel = data.mode === 'pair' ? 'stranger' : data.room;
      document.getElementById('room-name').textContent = '#' + roomLabel;
      document.getElementById('skip-btn').hidden = data.mode !== 'pair';
      if (!data.resumed) document.getElementById('messages').innerHTML = '';
      data.history.forEach(renderMessage);
      showScreen('chat');
      scrollToBottom();
      if (data.resumed) showToast('reconnected');
      if (cb) { cb = null; }
    });

    socket.on('searching', () => showScreen('searching'));

    socket.on('find-stranger-ack', () => socket.emit('find-stranger'));

    socket.on('stranger-left', () => {
      showToast('stranger disconnected');
      renderSystem('the stranger left. searching for someone new...');
      socket.emit('find-stranger');
    });

    socket.on('message', (msg) => { renderMessage(msg); scrollToBottom(); });
    socket.on('system', (text) => { renderSystem(text); scrollToBottom(); });
    socket.on('presence', (count) => { document.getElementById('presence-count').textContent = count; });

    socket.on('typing', (name) => {
      const el = document.getElementById('typing-indicator');
      el.textContent = name + ' is typing...';
      clearTimeout(typingTimeout);
      typingTimeout = setTimeout(() => { el.textContent = ''; }, 1800);
    });

    socket.on('reaction-update', ({ id, counts }) => updateReactions(id, counts));
    socket.on('disconnect', () => { socketReady = false; showToast('disconnected - reconnecting...'); });
    socket.on('connect_error', () => showToast('connection failed'));
  }

  // Auto-resume on load if session exists
  window.addEventListener('load', () => {
    if (getSessionId()) initSocket();
  });

  function renderSystem(text) {
    const el = document.createElement('div');
    el.className = 'system-msg';
    el.textContent = text;
    document.getElementById('messages').appendChild(el);
  }

  function renderMessage(msg) {
    const wrap = document.createElement('div');
    wrap.className = 'msg ' + (msg.from === myNickname ? 'mine' : 'theirs');
    wrap.dataset.id = msg.id;

    const meta = document.createElement('div');
    meta.className = 'msg-meta';
    const time = new Date(msg.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    meta.textContent = (msg.from === myNickname ? 'you' : msg.from) + ' . ' + time;
    wrap.appendChild(meta);

    if (msg.image) {
      const img = document.createElement('img');
      img.className = 'bubble-img';
      img.src = msg.image;
      img.loading = 'lazy';
      img.addEventListener('click', () => openLightbox(msg.image));
      img.addEventListener('contextmenu', (e) => { e.preventDefault(); openReactionPicker(e, msg.id); });
      let pt;
      img.addEventListener('touchstart', (e) => { pt = setTimeout(() => openReactionPicker(e, msg.id), 450); });
      img.addEventListener('touchend', () => clearTimeout(pt));
      wrap.appendChild(img);
    }

    if (msg.text) {
      const bubble = document.createElement('div');
      bubble.className = 'bubble';
      bubble.textContent = msg.text;
      bubble.addEventListener('contextmenu', (e) => { e.preventDefault(); openReactionPicker(e, msg.id); });
      let pt;
      bubble.addEventListener('touchstart', (e) => { pt = setTimeout(() => openReactionPicker(e, msg.id), 450); });
      bubble.addEventListener('touchend', () => clearTimeout(pt));
      bubble.addEventListener('dblclick', (e) => openReactionPicker(e, msg.id));
      wrap.appendChild(bubble);
    }

    const reactionsRow = document.createElement('div');
    reactionsRow.className = 'reactions-row';
    wrap.appendChild(reactionsRow);

    document.getElementById('messages').appendChild(wrap);
  }

  function updateReactions(msgId, counts) {
    const wrap = document.querySelector('.msg[data-id="' + msgId + '"]');
    if (!wrap) return;
    const row = wrap.querySelector('.reactions-row');
    row.innerHTML = '';
    for (const [emoji, count] of Object.entries(counts)) {
      const chip = document.createElement('div');
      chip.className = 'reaction-chip';
      chip.textContent = emoji + ' ' + count;
      chip.addEventListener('click', () => socket.emit('reaction', { id: msgId, emoji }));
      row.appendChild(chip);
    }
  }

  function scrollToBottom() {
    const el = document.getElementById('messages');
    el.scrollTop = el.scrollHeight;
  }

  const REACTION_EMOJIS = ['👍', '❤️', '😂', '😮', '😢', '🔥'];
  const reactionPopover = document.getElementById('reaction-popover');

  function openReactionPicker(e, msgId) {
    e.preventDefault();
    reactionPopover.innerHTML = '';
    REACTION_EMOJIS.forEach(emoji => {
      const btn = document.createElement('button');
      btn.textContent = emoji;
      btn.addEventListener('click', () => {
        socket.emit('reaction', { id: msgId, emoji });
        reactionPopover.classList.remove('active');
      });
      reactionPopover.appendChild(btn);
    });
    const x = e.touches ? e.touches[0].clientX : e.clientX;
    const y = e.touches ? e.touches[0].clientY : e.clientY;
    reactionPopover.style.left = Math.min(x, window.innerWidth - 260) + 'px';
    reactionPopover.style.top = Math.max(y - 60, 10) + 'px';
    reactionPopover.classList.add('active');
  }
  document.addEventListener('click', (e) => {
    if (!reactionPopover.contains(e.target)) reactionPopover.classList.remove('active');
  });

  // Connect: room mode
  document.getElementById('connect-btn').addEventListener('click', () => {
    const room = document.getElementById('room-input').value.trim() || 'lobby';
    initSocket(() => socket.emit('join', room));
  });
  document.getElementById('room-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.getElementById('connect-btn').click();
  });

  // Connect: stranger mode
  document.getElementById('find-btn').addEventListener('click', () => {
    initSocket(() => socket.emit('find-stranger'));
  });

  // Cancel search — just go back, remove from queue on server side via disconnect grace
  document.getElementById('cancel-search-btn').addEventListener('click', () => {
    if (socket) {
      socket.emit('exit-session');
      socket.disconnect();
      socket = null;
      socketReady = false;
    }
    clearSessionId();
    showScreen('login');
  });

  // Skip stranger
  document.getElementById('skip-btn').addEventListener('click', () => {
    document.getElementById('messages').innerHTML = '';
    if (socket) socket.emit('skip-stranger');
    showScreen('searching');
  });

  // Leave (explicit exit)
  document.getElementById('leave-btn').addEventListener('click', () => {
    if (socket) {
      socket.emit('exit-session');
      socket.disconnect();
      socket = null;
      socketReady = false;
    }
    clearSessionId();
    document.getElementById('messages').innerHTML = '';
    showScreen('login');
  });

  const textInput = document.getElementById('text-input');
  const composer = document.getElementById('composer');
  const imageBtn = document.getElementById('image-btn');
  const imageInput = document.getElementById('image-input');
  const imagePreview = document.getElementById('image-preview');
  const emojiBtn = document.getElementById('emoji-btn');
  const emojiPicker = document.getElementById('emoji-picker');

  textInput.addEventListener('input', () => { if (socket) socket.emit('typing'); });
  imageBtn.addEventListener('click', () => imageInput.click());

  imageInput.addEventListener('change', async () => {
    const file = imageInput.files[0];
    if (!file) return;
    if (file.size > 6 * 1024 * 1024) { showToast('image too large (max 6MB)'); imageInput.value = ''; return; }
    showToast('uploading...');
    const fd = new FormData();
    fd.append('image', file);
    try {
      const res = await fetch('/upload', { method: 'POST', body: fd });
      const data = await res.json();
      if (data.url) {
        pendingImage = data.url;
        imagePreview.innerHTML = '';
        const thumb = document.createElement('img');
        thumb.src = data.url;
        imagePreview.appendChild(thumb);
        const removeBtn = document.createElement('button');
        removeBtn.className = 'remove-img';
        removeBtn.textContent = 'remove';
        removeBtn.addEventListener('click', () => {
          pendingImage = null;
          imagePreview.classList.remove('active');
          imagePreview.innerHTML = '';
          imageInput.value = '';
        });
        imagePreview.appendChild(removeBtn);
        imagePreview.classList.add('active');
        showToast('image attached');
      } else { showToast('upload failed'); }
    } catch { showToast('upload failed'); }
  });

  composer.addEventListener('submit', (e) => {
    e.preventDefault();
    const text = textInput.value.trim();
    if (!text && !pendingImage) return;
    if (!socket) return;
    socket.emit('message', { text, image: pendingImage });
    textInput.value = '';
    pendingImage = null;
    imagePreview.classList.remove('active');
    imagePreview.innerHTML = '';
    imageInput.value = '';
    emojiPicker.classList.remove('active');
  });

  const EMOJI_LIST = ['😀','😂','😍','😎','🤔','😢','😡','😮','👍','👎','❤️','🔥','🎉','🙏','💀','😴','🥳','😏','😱','🤡','👀','✨','💯','🤝','😅','🙃','😬','🫠','🤯','😈','👻','🤖'];

  emojiBtn.addEventListener('click', () => {
    if (emojiPicker.classList.contains('active')) { emojiPicker.classList.remove('active'); return; }
    emojiPicker.innerHTML = '';
    EMOJI_LIST.forEach(emoji => {
      const btn = document.createElement('button');
      btn.textContent = emoji;
      btn.type = 'button';
      btn.addEventListener('click', () => { textInput.value += emoji; textInput.focus(); });
      emojiPicker.appendChild(btn);
    });
    emojiPicker.classList.add('active');
  });

  const lightbox = document.getElementById('lightbox');
  const lightboxImg = document.getElementById('lightbox-img');
  function openLightbox(src) { lightboxImg.src = src; lightbox.classList.add('active'); }
  lightbox.addEventListener('click', () => { lightbox.classList.remove('active'); lightboxImg.src = ''; });

  let toastTimeout;
  function showToast(msg) {
    const el = document.getElementById('toast');
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => el.classList.remove('show'), 2200);
  }
})();
