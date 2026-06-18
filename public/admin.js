(() => {
  const loginScreen = document.getElementById('login-screen');
  const dashboard = document.getElementById('dashboard');

  function showToast(msg) {
    const el = document.getElementById('toast');
    el.textContent = msg;
    el.classList.add('show');
    setTimeout(() => el.classList.remove('show'), 2500);
  }

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      ...opts,
      headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
      credentials: 'same-origin',
    });
    if (res.status === 401) {
      showDashboard(false);
      throw new Error('unauthenticated');
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'request failed');
    return data;
  }

  function showDashboard(show) {
    loginScreen.classList.toggle('hidden', show);
    dashboard.classList.toggle('hidden', !show);
  }

  async function checkAuth() {
    try {
      await api('/admin/api/me');
      showDashboard(true);
      loadOverview();
    } catch {
      showDashboard(false);
    }
  }

  document.getElementById('login-btn').addEventListener('click', async () => {
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    const errEl = document.getElementById('login-error');
    errEl.textContent = '';
    try {
      await api('/admin/api/login', { method: 'POST', body: JSON.stringify({ username, password }) });
      showDashboard(true);
      loadOverview();
    } catch (e) {
      errEl.textContent = e.message === 'unauthenticated' ? 'invalid credentials' : (e.message || 'login failed');
    }
  });

  document.getElementById('logout-btn').addEventListener('click', async () => {
    await api('/admin/api/logout', { method: 'POST' });
    showDashboard(false);
  });

  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('panel-' + tab.dataset.panel).classList.add('active');
      if (tab.dataset.panel === 'bans') loadBans();
      if (tab.dataset.panel === 'words') loadWords();
      if (tab.dataset.panel === 'logs') loadLogs();
      if (tab.dataset.panel === 'overview') loadOverview();
    });
  });

  async function loadOverview() {
    try {
      const data = await api('/admin/api/overview');
      const a = data.analytics || {};
      const statGrid = document.getElementById('stat-grid');
      statGrid.innerHTML = `
        <div class="stat-card"><div class="num">${a.totalVisitorsEver ?? '-'}</div><div class="label">total visitors ever</div></div>
        <div class="stat-card"><div class="num">${a.activeToday ?? '-'}</div><div class="label">active today</div></div>
        <div class="stat-card"><div class="num">${a.activeThisWeek ?? '-'}</div><div class="label">active this week</div></div>
        <div class="stat-card"><div class="num">${data.activeSessions.length}</div><div class="label">online right now</div></div>
        <div class="stat-card"><div class="num">${a.peakConcurrent ?? '-'}</div><div class="label">peak concurrent</div></div>
        <div class="stat-card"><div class="num">${a.pairingsTotal ?? '-'}</div><div class="label">total pairings</div></div>
        <div class="stat-card"><div class="num">${a.messagesToday ?? '-'}</div><div class="label">messages today</div></div>
        <div class="stat-card"><div class="num">${a.messagesTotal ?? '-'}</div><div class="label">messages total</div></div>
        <div class="stat-card"><div class="num">${data.waitingCount}</div><div class="label">in queue</div></div>
        <div class="stat-card"><div class="num">${data.bans.length}</div><div class="label">total bans</div></div>
      `;
      const tbody = document.getElementById('sessions-body');
      if (data.activeSessions.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="empty-state">no active sessions</td></tr>';
      } else {
        tbody.innerHTML = data.activeSessions.map(s => `
          <tr>
            <td>${escapeHtml(s.nickname || '-')}</td>
            <td>${escapeHtml(s.mode || '-')}</td>
            <td><span class="badge ${s.connected ? 'live' : 'dead'}">${s.connected ? 'online' : 'offline'}</span></td>
          </tr>
        `).join('');
      }
    } catch (e) {}
  }

  async function loadBans() {
    try {
      const data = await api('/admin/api/overview');
      const tbody = document.getElementById('bans-body');
      if (data.bans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">no bans</td></tr>';
        return;
      }
      tbody.innerHTML = data.bans.map(b => {
        const status = b.bannedUntil === null ? 'permanent' : (b.bannedUntil > Date.now() ? new Date(b.bannedUntil).toLocaleString() : 'expired');
        return `
          <tr>
            <td>${escapeHtml(b.ip)}</td>
            <td>${b.offenses}</td>
            <td><span class="badge ${b.bannedUntil === null || b.bannedUntil > Date.now() ? 'flagged' : 'dead'}">${status}</span></td>
            <td>${escapeHtml(b.reason || '-')}</td>
            <td><button class="action-btn success" data-unban="${escapeHtml(b.ip)}">unban</button></td>
          </tr>
        `;
      }).join('');
      tbody.querySelectorAll('[data-unban]').forEach(btn => {
        btn.addEventListener('click', async () => {
          await api('/admin/api/unban', { method: 'POST', body: JSON.stringify({ ip: btn.dataset.unban }) });
          showToast('unbanned ' + btn.dataset.unban);
          loadBans();
        });
      });
    } catch (e) {}
  }

  document.getElementById('ban-submit-btn').addEventListener('click', async () => {
    const ip = document.getElementById('ban-ip-input').value.trim();
    const duration = document.getElementById('ban-duration').value;
    const reason = document.getElementById('ban-reason-input').value.trim();
    if (!ip) return showToast('enter an IP first');
    const body = { ip, reason };
    if (duration === 'permanent') body.permanent = true;
    else body.durationHours = Number(duration);
    try {
      await api('/admin/api/ban', { method: 'POST', body: JSON.stringify(body) });
      showToast('banned ' + ip);
      document.getElementById('ban-ip-input').value = '';
      document.getElementById('ban-reason-input').value = '';
      loadBans();
    } catch (e) { showToast(e.message); }
  });

  let wordCache = { severe: [], threat: [] };

  async function loadWords() {
    try {
      const data = await api('/admin/api/words');
      wordCache = data;
      renderTags('severe');
      renderTags('threat');
    } catch (e) {}
  }

  function renderTags(kind) {
    const container = document.getElementById(kind + '-tags');
    const list = wordCache[kind] || [];
    if (list.length === 0) {
      container.innerHTML = '<span class="empty-state" style="display:inline-block;padding:8px 0">no words yet</span>';
      return;
    }
    container.innerHTML = list.map((w, i) => `
      <span class="word-tag">${escapeHtml(w)}<button data-kind="${kind}" data-idx="${i}">×</button></span>
    `).join('');
    container.querySelectorAll('button').forEach(btn => {
      btn.addEventListener('click', async () => {
        const k = btn.dataset.kind;
        const idx = Number(btn.dataset.idx);
        wordCache[k] = wordCache[k].filter((_, i) => i !== idx);
        await saveWords(k);
        renderTags(k);
      });
    });
  }

  async function saveWords(kind) {
    try {
      await api('/admin/api/words', { method: 'POST', body: JSON.stringify({ kind, list: wordCache[kind] }) });
      showToast(kind + ' list updated');
    } catch (e) { showToast(e.message); }
  }

  document.getElementById('severe-add-btn').addEventListener('click', async () => {
    const input = document.getElementById('severe-input');
    const val = input.value.trim();
    if (!val) return;
    wordCache.severe.push(val);
    input.value = '';
    await saveWords('severe');
    renderTags('severe');
  });

  document.getElementById('threat-add-btn').addEventListener('click', async () => {
    const input = document.getElementById('threat-input');
    const val = input.value.trim();
    if (!val) return;
    wordCache.threat.push(val);
    input.value = '';
    await saveWords('threat');
    renderTags('threat');
  });

  async function loadLogs() {
    try {
      const data = await api('/admin/api/logs');
      const tbody = document.getElementById('logs-body');
      if (data.logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">no recent messages</td></tr>';
        return;
      }
      tbody.innerHTML = data.logs.map(l => `
        <tr>
          <td>${new Date(l.time).toLocaleString()}</td>
          <td>${escapeHtml(l.nickname || '-')}</td>
          <td>${escapeHtml(l.ip || '-')}</td>
          <td class="msg-text">${escapeHtml(l.text || (l.image ? '[image]' : ''))}</td>
          <td>${l.flagged ? `<span class="badge flagged">${escapeHtml(l.flagged)}</span>` : ''}</td>
        </tr>
      `).join('');
    } catch (e) {}
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }

  checkAuth();
})();
