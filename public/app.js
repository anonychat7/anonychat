(() => {
  const screens = {
    login: document.getElementById('screen-login'),
    about: document.getElementById('screen-about'),
    searching: document.getElementById('screen-searching'),
    chat: document.getElementById('screen-chat'),
    banned: document.getElementById('screen-banned'),
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

  function getSessionId() { try { return localStorage.getItem('anonychat-session') || null; } catch { return null; } }
  function setSessionId(id) { try { localStorage.setItem('anonychat-session', id); } catch {} }
  function clearSessionId() { try { localStorage.removeItem('anonychat-session'); } catch {} }

  const SEARCH_LINES = [
    'looking for someone to talk to…',
    'scanning the crowd…',
    'still searching…',
    'this might take a moment…',
    'almost there…',
    'finding someone new…',
  ];
  let searchLineInterval = null;
  function startSearchLines() {
    const el = document.getElementById('searching-line');
    let i = 0;
    el.style.opacity = 1;
    el.textContent = SEARCH_LINES[0];
    clearInterval(searchLineInterval);
    searchLineInterval = setInterval(() => {
      i = (i + 1) % SEARCH_LINES.length;
      el.style.opacity = 0;
      setTimeout(() => { el.textContent = SEARCH_LINES[i]; el.style.opacity = 1; }, 280);
    }, 2600);
  }
  function stopSearchLines() { clearInterval(searchLineInterval); }

  let socket = null;
  let myNickname = '';
  let pendingImage = null;
  let typingTimeout = null;
  let socketReady = false;

  function initSocket(cb) {
    if (socket && socketReady) { if (cb) cb(); return; }
    if (socket) { if (cb) socket.once('session-ready-cb', cb); return; }

    socket = io({ transports: ['websocket', 'polling'] });

    socket.on('connect', () => {
      socket.emit('resume-session', getSessionId());
    });

    socket.on('connect_error', (err) => {
      if (err && err.message === 'banned') {
        showBannedScreen({});
      } else {
        showToast('connection failed');
      }
    });

    socket.on('session', ({ sessionId }) => {
      setSessionId(sessionId);
      socketReady = true;
      if (cb) { cb(); cb = null; }
    });

    socket.on('joined', (data) => {
      socketReady = true;
      myNickname = data.nickname;
      stopSearchLines();
      document.getElementById('skip-btn').hidden = false;
      document.getElementById('messages').innerHTML = '';
      showScreen('chat');
      if (data.resumed) showToast('reconnected');
      if (cb) cb = null;
    });

    socket.on('searching', () => {
      showScreen('searching');
      startSearchLines();
    });

    socket.on('find-stranger-ack', () => socket.emit('find-stranger'));

    socket.on('stranger-left', () => {
      showToast('stranger disconnected');
      renderSystem('the stranger left. finding someone new…');
      socket.emit('find-stranger');
    });

    socket.on('message', (msg) => { renderMessage(msg); scrollToBottom(); });
    socket.on('system', (text) => { renderSystem(text); scrollToBottom(); });
    socket.on('presence', () => {});

    socket.on('typing', () => {
      const el = document.getElementById('typing-indicator');
      el.textContent = 'stranger is typing…';
      clearTimeout(typingTimeout);
      typingTimeout = setTimeout(() => { el.textContent = ''; }, 1800);
    });

    socket.on('moderation-warning', ({ message }) => {
      showWarningBanner(message);
    });

    socket.on('banned', (info) => {
      showBannedScreen(info);
    });

    socket.on('disconnect', () => { socketReady = false; });
  }

  window.addEventListener('load', () => {
    if (getSessionId()) initSocket();
  });

  function showWarningBanner(message) {
    const el = document.getElementById('warning-banner');
    document.getElementById('warning-text').textContent = '⚠ ' + message;
    el.classList.add('show');
    setTimeout(() => el.classList.remove('show'), 6000);
  }

  function showBannedScreen(info) {
    const msgEl = document.getElementById('banned-message');
    if (info.permanent) {
      msgEl.textContent = "You've been permanently banned from AnonyChat for repeated violations of our rules against threats of violence.";
    } else if (info.bannedUntil) {
      const until = new Date(info.bannedUntil);
      msgEl.textContent = "You've been temporarily banned from AnonyChat until " + until.toLocaleString() + " due to a violation of our rules against threats of violence.";
    } else {
      msgEl.textContent = "You've been restricted from AnonyChat due to a violation of our rules.";
    }
    clearSessionId();
    if (socket) { socket.disconnect(); socket = null; socketReady = false; }
    showScreen('banned');
  }

  function renderSystem(text) {
    const el = document.createElement('div');
    el.className = 'system-msg';
    el.textContent = text;
    document.getElementById('messages').appendChild(el);
  }

  function renderMessage(msg) {
    const wrap = document.createElement('div');
    wrap.className = 'msg ' + (msg.from === myNickname ? 'mine' : 'theirs');

    const meta = document.createElement('div');
    meta.className = 'msg-meta';
    const time = new Date(msg.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    meta.textContent = (msg.from === myNickname ? 'you' : 'stranger') + ' · ' + time;
    wrap.appendChild(meta);

    if (msg.image) {
      const img = document.createElement('img');
      img.className = 'bubble-img';
      img.src = msg.image;
      img.loading = 'lazy';
      img.addEventListener('click', () => openLightbox(msg.image));
      wrap.appendChild(img);
    }

    if (msg.text) {
      const bubble = document.createElement('div');
      bubble.className = 'bubble';
      bubble.textContent = msg.text;
      wrap.appendChild(bubble);
    }

    document.getElementById('messages').appendChild(wrap);
  }

  function scrollToBottom() {
    const el = document.getElementById('messages');
    el.scrollTop = el.scrollHeight;
  }

  document.getElementById('find-btn').addEventListener('click', () => {
    initSocket(() => socket.emit('find-stranger'));
  });

  document.getElementById('cancel-search-btn').addEventListener('click', () => {
    stopSearchLines();
    if (socket) socket.emit('cancel-search');
    showScreen('login');
  });

  document.getElementById('skip-btn').addEventListener('click', () => {
    document.getElementById('messages').innerHTML = '';
    if (socket) socket.emit('skip-stranger');
    showScreen('searching');
    startSearchLines();
  });

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

  textInput.addEventListener('input', () => { if (socket) socket.emit('typing'); });
  imageBtn.addEventListener('click', () => imageInput.click());

  imageInput.addEventListener('change', async () => {
    const file = imageInput.files[0];
    if (!file) return;
    if (file.size > 4 * 1024 * 1024) { showToast('image too large (max 4MB)'); imageInput.value = ''; return; }
    showToast('uploading…');
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
      } else if (res.status === 403) {
        showToast('you are banned');
      } else {
        showToast('upload failed');
      }
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
