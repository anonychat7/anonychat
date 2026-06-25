require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xss = require('xss');
const { Redis } = require('@upstash/redis');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);

app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:", "https://*.giphy.com"],
      connectSrc: ["'self'", "ws:", "wss:"],
      fontSrc: ["'self'"],
    }
  }
}));

const limiter = rateLimit({ windowMs: 60*1000, max: 60, message: { error: 'Too many requests.' } });
app.use('/upload', limiter);

const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, message: { error: 'Too many login attempts, try again later.' } });

const io = new Server(server, {
  maxHttpBufferSize: 2e6,
  cors: { origin: false },
  pingTimeout: 20000,
  pingInterval: 25000,
});

const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

let redis = null;
if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
  redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN,
  });
  console.log('Upstash Redis connected');
} else {
  console.warn('UPSTASH credentials missing - bans/admin/logs will NOT persist (in-memory fallback)');
}

const memBans = new Map();
const memWords = { severe: [], threat: [] };
const memLogs = [];

async function getBan(ip) {
  if (redis) return (await redis.get('ban:' + ip)) || null;
  return memBans.get(ip) || null;
}
async function setBan(ip, rec) {
  if (redis) await redis.set('ban:' + ip, rec);
  else memBans.set(ip, rec);
}
async function deleteBan(ip) {
  if (redis) await redis.del('ban:' + ip);
  else memBans.delete(ip);
}
async function listBans() {
  if (redis) {
    const keys = await redis.keys('ban:*');
    const results = [];
    for (const k of keys) {
      const rec = await redis.get(k);
      if (rec) results.push({ ip: k.replace('ban:', ''), ...rec });
    }
    return results;
  }
  return Array.from(memBans.entries()).map(([ip, rec]) => ({ ip, ...rec }));
}

function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

async function isBanned(ip) {
  const rec = await getBan(ip);
  if (!rec) return false;
  if (rec.bannedUntil === null) return true;
  if (rec.bannedUntil && Date.now() < rec.bannedUntil) return true;
  return false;
}

function banDurationForOffense(offenseCount) {
  if (offenseCount === 2) return 24*60*60*1000;
  if (offenseCount === 3) return 7*24*60*60*1000;
  return null;
}

async function recordOffense(ip) {
  let rec = await getBan(ip);
  if (!rec) rec = { offenses: 0, bannedUntil: 0, warned: false };
  rec.offenses += 1;
  if (rec.offenses === 1) {
    rec.warned = true;
    await setBan(ip, rec);
    return { action: 'warn' };
  }
  const duration = banDurationForOffense(rec.offenses);
  rec.bannedUntil = duration ? Date.now() + duration : null;
  await setBan(ip, rec);
  return { action: 'ban', permanent: duration === null, until: rec.bannedUntil };
}

async function instantPermanentBan(ip, reason) {
  let rec = await getBan(ip);
  if (!rec) rec = { offenses: 0, bannedUntil: 0, warned: false };
  rec.offenses += 10;
  rec.bannedUntil = null;
  rec.reason = reason || rec.reason;
  await setBan(ip, rec);
}

const DEFAULT_SEVERE_WORDS = [
  'child porn', 'childporn', 'cp pic', 'cp video', 'lolita sex', 'underage sex',
  'underage nude', 'child sex', 'child abuse', 'minor sex', 'minor nude', 'pedo'
];
const DEFAULT_THREAT_PHRASES = [
  'ill kill you', 'i will kill you', 'i gonna kill you', 'gonna kill you', 'kill you',
  'kill yourself', 'kys', 'ill murder you', 'i will murder you', 'gonna murder you',
  'murder you', 'behead you', 'beheading', 'hunt you down', 'how to make a bomb',
  'how to kill someone', 'i want to kill', 'gonna shoot up', 'i will bomb',
  'stab you', 'shoot you', 'slaughter', 'massacre'
];

async function getWordList(kind) {
  if (redis) {
    const data = await redis.get('words:' + kind);
    if (data && Array.isArray(data)) return data;
    const defaults = kind === 'severe' ? DEFAULT_SEVERE_WORDS : DEFAULT_THREAT_PHRASES;
    await redis.set('words:' + kind, defaults);
    return defaults;
  }
  if (memWords[kind].length === 0) {
    memWords[kind] = kind === 'severe' ? [...DEFAULT_SEVERE_WORDS] : [...DEFAULT_THREAT_PHRASES];
  }
  return memWords[kind];
}
async function setWordList(kind, list) {
  if (redis) await redis.set('words:' + kind, list);
  else memWords[kind] = list;
}

let severeWordsCache = [...DEFAULT_SEVERE_WORDS];
let threatWordsCache = [...DEFAULT_THREAT_PHRASES];
async function refreshWordCaches() {
  severeWordsCache = await getWordList('severe');
  threatWordsCache = await getWordList('threat');
}
refreshWordCaches();
setInterval(refreshWordCaches, 30000);

function normalizeForThreatCheck(text) {
  let t = text.toLowerCase();
  t = t.replace(/'/g, '');
  t = t.replace(/!/g, 'i').replace(/1/g, 'i').replace(/0/g, 'o').replace(/3/g, 'e').replace(/4/g, 'a').replace(/7/g, 't').replace(/5/g, 's').replace(/@/g, 'a');
  t = t.replace(/[^a-z0-9\s]/g, '');
  t = t.replace(/\s+/g, ' ').trim();
  return t;
}

function detectSevere(text) {
  const norm = normalizeForThreatCheck(text);
  return severeWordsCache.some(w => norm.includes(normalizeForThreatCheck(w)));
}
function detectThreat(text) {
  const norm = normalizeForThreatCheck(text);
  return threatWordsCache.some(w => norm.includes(normalizeForThreatCheck(w)));
}

const LOG_RETENTION_MS = 24 * 60 * 60 * 1000;

async function logMessage(entry) {
  if (redis) {
    const key = 'logs:' + Date.now() + ':' + crypto.randomBytes(4).toString('hex');
    await redis.set(key, entry, { ex: 86400 });
  } else {
    memLogs.push({ ...entry, _key: Date.now() });
    const cutoff = Date.now() - LOG_RETENTION_MS;
    while (memLogs.length && memLogs[0]._key < cutoff) memLogs.shift();
    if (memLogs.length > 1000) memLogs.shift();
  }
}
async function getRecentLogs(limit) {
  if (redis) {
    const keys = await redis.keys('logs:*');
    keys.sort().reverse();
    const slice = keys.slice(0, limit || 200);
    const results = [];
    for (const k of slice) {
      const v = await redis.get(k);
      if (v) results.push(v);
    }
    return results;
  }
  return memLogs.slice(-(limit || 200)).reverse();
}

// ---------- Analytics ----------
function dayKey(d = new Date()) { return d.toISOString().slice(0, 10); }

async function trackNewVisitor(sessionId) {
  if (!redis) return;
  await redis.sadd('analytics:all_sessions', sessionId);
  await redis.sadd('analytics:daily:' + dayKey(), sessionId);
}
async function trackMessage() {
  if (!redis) return;
  await redis.incr('analytics:messages_total');
  await redis.incr('analytics:messages:' + dayKey());
}
async function trackPairing() {
  if (!redis) return;
  await redis.incr('analytics:pairings_total');
}
async function trackPeakConcurrent(current) {
  if (!redis) return;
  const peak = Number(await redis.get('analytics:peak_concurrent')) || 0;
  if (current > peak) await redis.set('analytics:peak_concurrent', current);
}

async function getAnalytics() {
  if (!redis) {
    return {
      totalVisitorsEver: sessions.size,
      activeToday: io.sockets.sockets.size,
      activeThisWeek: io.sockets.sockets.size,
      messagesTotal: 0,
      messagesToday: 0,
      pairingsTotal: 0,
      peakConcurrent: io.sockets.sockets.size,
    };
  }
  const totalVisitorsEver = await redis.scard('analytics:all_sessions');
  const activeToday = await redis.scard('analytics:daily:' + dayKey());

  const weekSet = new Set();
  for (let i = 0; i < 7; i++) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const members = await redis.smembers('analytics:daily:' + dayKey(d));
    members.forEach(m => weekSet.add(m));
  }

  const messagesTotal = Number(await redis.get('analytics:messages_total')) || 0;
  const messagesToday = Number(await redis.get('analytics:messages:' + dayKey())) || 0;
  const pairingsTotal = Number(await redis.get('analytics:pairings_total')) || 0;
  const peakConcurrent = Number(await redis.get('analytics:peak_concurrent')) || 0;

  return { totalVisitorsEver, activeToday, activeThisWeek: weekSet.size, messagesTotal, messagesToday, pairingsTotal, peakConcurrent };
}

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

async function getAdminUser(username) {
  if (redis) return await redis.get('admin:user:' + username.toLowerCase());
  return null;
}

function requireAdmin(req, res, next) {
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: 'not authenticated' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.admin = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'invalid or expired session' });
  }
}

app.post('/admin/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const user = await getAdminUser(username);
  if (!user) return res.status(401).json({ error: 'invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });

  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '12h' });
  res.cookie('admin_token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 12 * 60 * 60 * 1000,
  });
  res.json({ ok: true });
});

app.post('/admin/api/logout', (req, res) => {
  res.clearCookie('admin_token');
  res.json({ ok: true });
});

app.get('/admin/api/me', requireAdmin, (req, res) => {
  res.json({ username: req.admin.username });
});

app.get('/admin/api/overview', requireAdmin, async (req, res) => {
  const activeSessions = Array.from(sessions.entries()).map(([sid, s]) => ({
    sessionId: sid,
    nickname: s.nickname,
    mode: s.mode,
    connected: !!s.socketId && !!io.sockets.sockets.get(s.socketId),
  }));
  const bans = await listBans();
  const analytics = await getAnalytics();
  res.json({
    activeSessions,
    waitingCount: waitingQueue.length,
    totalConnections: io.sockets.sockets.size,
    bans,
    analytics,
  });
});

app.post('/admin/api/ban', requireAdmin, async (req, res) => {
  const { ip, durationHours, permanent, reason } = req.body || {};
  if (!ip) return res.status(400).json({ error: 'ip required' });
  const rec = { offenses: 99, warned: true, reason: reason || 'manual admin ban' };
  rec.bannedUntil = permanent ? null : Date.now() + (Number(durationHours) || 24) * 60 * 60 * 1000;
  await setBan(ip, rec);
  res.json({ ok: true });
});

app.post('/admin/api/unban', requireAdmin, async (req, res) => {
  const { ip } = req.body || {};
  if (!ip) return res.status(400).json({ error: 'ip required' });
  await deleteBan(ip);
  res.json({ ok: true });
});

app.get('/admin/api/words', requireAdmin, async (req, res) => {
  res.json({
    severe: await getWordList('severe'),
    threat: await getWordList('threat'),
  });
});

app.post('/admin/api/words', requireAdmin, async (req, res) => {
  const { kind, list } = req.body || {};
  if (kind !== 'severe' && kind !== 'threat') return res.status(400).json({ error: 'invalid kind' });
  if (!Array.isArray(list)) return res.status(400).json({ error: 'list must be an array' });
  const cleaned = list.map(w => String(w).slice(0, 100)).filter(Boolean).slice(0, 500);
  await setWordList(kind, cleaned);
  await refreshWordCaches();
  res.json({ ok: true, count: cleaned.length });
});

app.get('/admin/api/logs', requireAdmin, async (req, res) => {
  const logs = await getRecentLogs(300);
  res.json({ logs });
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

const IMAGE_SIGNATURES = [
  [0xFF,0xD8,0xFF],
  [0x89,0x50,0x4E,0x47],
  [0x47,0x49,0x46],
  [0x52,0x49,0x46,0x46],
];
function isRealImage(buffer) {
  return IMAGE_SIGNATURES.some(sig => sig.every((b,i) => buffer[i] === b));
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowed = ['.png','.jpg','.jpeg','.gif','.webp'];
    if (!allowed.includes(ext)) return cb(new Error('Invalid type'));
    cb(null, crypto.randomBytes(16).toString('hex') + ext);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 4*1024*1024, files: 1 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.png','.jpg','.jpeg','.gif','.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, allowed.includes(ext) && file.mimetype.startsWith('image/'));
  }
});

app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0, etag: true }));

app.post('/upload', async (req, res) => {
  const ip = getClientIp(req);
  if (await isBanned(ip)) return res.status(403).json({ error: 'banned' });
  upload.single('image')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message || 'Upload failed' });
    if (!req.file) return res.status(400).json({ error: 'No image' });
    const buf = fs.readFileSync(req.file.path);
    if (!isRealImage(buf)) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'Invalid image file' });
    }
    res.json({ url: '/uploads/' + req.file.filename });
  });
});

// ---------- GIPHY proxy (keeps API key server-side, never exposed to browser) ----------
const gifLimiter = rateLimit({ windowMs: 60*1000, max: 30, message: { error: 'Too many GIF searches, slow down.' } });

app.get('/gif/search', gifLimiter, async (req, res) => {
  const ip = getClientIp(req);
  if (await isBanned(ip)) return res.status(403).json({ error: 'banned' });
  const apiKey = process.env.GIPHY_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'GIF search not configured' });

  const q = (req.query.q || '').toString().slice(0, 100);
  const url = q
    ? `https://api.giphy.com/v1/gifs/search?api_key=${apiKey}&q=${encodeURIComponent(q)}&limit=24&rating=pg-13`
    : `https://api.giphy.com/v1/gifs/trending?api_key=${apiKey}&limit=24&rating=pg-13`;

  try {
    const giphyRes = await fetch(url);
    const data = await giphyRes.json();
    const gifs = (data.data || []).map(g => ({
      id: g.id,
      preview: g.images.fixed_height_small?.url || g.images.fixed_height?.url,
      full: g.images.fixed_height?.url || g.images.original?.url,
    }));
    res.json({ gifs });
  } catch (e) {
    res.status(502).json({ error: 'GIF service unavailable' });
  }
});

const waitingQueue = [];
const pairings = new Map();
const sessions = new Map();
const socketRateLimits = new Map();
const GRACE_MS = 45000;
const MSG_RATE_LIMIT = 20;
const MSG_RATE_WINDOW = 10000;

const adjectives = ['Mysterious','Silent','Curious','Hidden','Lone','Shadow','Quiet','Wandering','Unknown','Masked','Drifting','Nameless','Cryptic','Phantom','Velvet','Electric','Wild','Frozen','Golden','Crimson'];
const nouns = ['Fox','Owl','Wolf','Raven','Tiger','Ghost','Falcon','Panther','Cobra','Eagle','Lynx','Otter','Hawk','Crow','Stag','Dragon','Phoenix','Viper','Shark','Wraith'];

function randomNickname() {
  return adjectives[Math.floor(Math.random()*adjectives.length)] + nouns[Math.floor(Math.random()*nouns.length)] + Math.floor(Math.random()*99);
}

function sanitize(str) {
  if (typeof str !== 'string') return '';
  return xss(str.trim()).slice(0, 2000);
}

function checkMsgRate(socketId) {
  const now = Date.now();
  if (!socketRateLimits.has(socketId)) {
    socketRateLimits.set(socketId, { count: 1, resetAt: now + MSG_RATE_WINDOW });
    return true;
  }
  const rl = socketRateLimits.get(socketId);
  if (now > rl.resetAt) { rl.count = 1; rl.resetAt = now + MSG_RATE_WINDOW; return true; }
  if (rl.count >= MSG_RATE_LIMIT) return false;
  rl.count++;
  return true;
}

function pairRoomId(a, b) { return 'pair_' + [a,b].sort().join('_'); }

function tryMatch(socket) {
  while (waitingQueue.length) {
    const candidateId = waitingQueue[0];
    const candidateSocket = io.sockets.sockets.get(candidateId);
    const sameSession = candidateSocket && socket.data.sessionId && candidateSocket.data.sessionId === socket.data.sessionId;
    if (!candidateSocket || candidateId === socket.id || candidateSocket.data.mode !== 'matching' || sameSession) {
      waitingQueue.shift();
      continue;
    }
    waitingQueue.shift();
    return candidateSocket;
  }
  return null;
}

function clearPairing(sid) {
  const partnerSid = pairings.get(sid);
  pairings.delete(sid);
  if (partnerSid) pairings.delete(partnerSid);
  return partnerSid;
}

setInterval(() => {}, 1000*60*14);

io.use(async (socket, next) => {
  const ip = getClientIp(socket.request);
  socket.data.ip = ip;
  if (await isBanned(ip)) return next(new Error('banned'));
  next();
});

io.on('connection', (socket) => {
  let currentRoom = null;
  let sessionId = null;
  let resumed = false;
  const ip = socket.data.ip;
  socket.data.nickname = randomNickname();

  socket.on('resume-session', async (sid) => {
    if (await isBanned(ip)) { socket.emit('banned', await getBan(ip)); socket.disconnect(true); return; }
    if (sid && (typeof sid !== 'string' || sid.length > 64)) return;

    if (sid && sessions.has(sid)) {
      const sess = sessions.get(sid);
      if (sess.disconnectTimer) { clearTimeout(sess.disconnectTimer); sess.disconnectTimer = null; }
      sessionId = sid;
      sess.socketId = socket.id;
      socket.data.sessionId = sessionId;
      socket.data.nickname = sess.nickname;

      if (sess.mode === 'pair' && sess.room) {
        const partnerSid = pairings.get(sessionId);
        const partnerSess = partnerSid ? sessions.get(partnerSid) : null;
        const partnerLive = partnerSess && partnerSess.socketId && io.sockets.sockets.get(partnerSess.socketId);
        if (partnerLive) {
          currentRoom = sess.room;
          socket.join(currentRoom);
          socket.data.room = currentRoom;
          socket.data.mode = 'pair';
          socket.emit('joined', { mode: 'pair', resumed: true, nickname: socket.data.nickname, partnerNickname: partnerSess.nickname });
          io.to(currentRoom).emit('presence', 2);
          resumed = true;
        } else {
          if (partnerSid) { pairings.delete(sessionId); pairings.delete(partnerSid); }
          sessions.delete(sessionId);
          sessionId = null;
        }
      } else if (sess.mode === 'matching') {
        const idx = waitingQueue.indexOf(sess.socketId);
        if (idx !== -1) waitingQueue.splice(idx, 1);
        sessions.delete(sessionId);
        sessionId = null;
      } else {
        sessions.delete(sessionId);
        sessionId = null;
      }
    }

    if (!resumed) {
      sessionId = sid || crypto.randomBytes(8).toString('hex');
      sessions.set(sessionId, { nickname: socket.data.nickname, mode: null, room: null, socketId: socket.id, disconnectTimer: null });
      socket.data.sessionId = sessionId;
      socket.emit('session', { sessionId, nickname: socket.data.nickname });
      await trackNewVisitor(sessionId);
      await trackPeakConcurrent(io.sockets.sockets.size);
    }
  });

  socket.on('find-stranger', async () => {
    if (await isBanned(ip)) { socket.emit('banned', await getBan(ip)); socket.disconnect(true); return; }
    if (currentRoom) { socket.leave(currentRoom); currentRoom = null; }
    socket.data.mode = 'matching';
    if (sessionId && sessions.has(sessionId)) {
      const s = sessions.get(sessionId);
      s.mode = 'matching';
      s.room = null;
    }

    for (let i = waitingQueue.length - 1; i >= 0; i--) {
      const qSocket = io.sockets.sockets.get(waitingQueue[i]);
      if (!qSocket || (sessionId && qSocket.data.sessionId === sessionId && qSocket.id !== socket.id)) {
        waitingQueue.splice(i, 1);
      }
    }

    const partnerSocket = tryMatch(socket);
    if (partnerSocket) {
      const roomId = pairRoomId(socket.id, partnerSocket.id);
      socket.join(roomId); partnerSocket.join(roomId);
      const mySid = sessionId;
      const theirSid = partnerSocket.data.sessionId;
      if (mySid && theirSid) { pairings.set(mySid, theirSid); pairings.set(theirSid, mySid); }
      socket.data.mode = 'pair'; socket.data.room = roomId;
      partnerSocket.data.mode = 'pair'; partnerSocket.data.room = roomId;
      if (sessionId && sessions.has(sessionId)) { const s = sessions.get(sessionId); s.mode = 'pair'; s.room = roomId; }
      if (theirSid && sessions.has(theirSid)) { const s = sessions.get(theirSid); s.mode = 'pair'; s.room = roomId; }
      currentRoom = roomId;
      socket.emit('joined', { mode: 'pair', nickname: socket.data.nickname, partnerNickname: partnerSocket.data.nickname });
      partnerSocket.emit('joined', { mode: 'pair', nickname: partnerSocket.data.nickname, partnerNickname: socket.data.nickname });
      io.to(roomId).emit('system', 'stranger connected');
      io.to(roomId).emit('presence', 2);
      await trackPairing();
    } else {
      waitingQueue.push(socket.id);
      socket.emit('searching');
    }
  });

  function handleStrangerLeave(sock, wantsRematch) {
    const sid = sock.data.sessionId;
    const roomId = sock.data.room;
    const partnerSid = sid ? clearPairing(sid) : null;
    if (partnerSid) {
      const partnerSess = sessions.get(partnerSid);
      if (partnerSess && partnerSess.socketId) {
        const ps = io.sockets.sockets.get(partnerSess.socketId);
        if (ps) {
          ps.emit('stranger-left');
          if (roomId) ps.leave(roomId);
          ps.data.mode = null;
          ps.data.room = null;
        }
      }
      if (partnerSess) { partnerSess.mode = null; partnerSess.room = null; }
    }
    if (roomId) sock.leave(roomId);
    sock.data.mode = null; sock.data.room = null; currentRoom = null;
    if (sid && sessions.has(sid)) { const s = sessions.get(sid); s.mode = null; s.room = null; }
    const idx = waitingQueue.indexOf(sock.id);
    if (idx !== -1) waitingQueue.splice(idx, 1);
    if (wantsRematch) sock.emit('find-stranger-ack');
  }

  socket.on('skip-stranger', () => handleStrangerLeave(socket, true));

  socket.on('cancel-search', () => {
    const idx = waitingQueue.indexOf(socket.id);
    if (idx !== -1) waitingQueue.splice(idx, 1);
    socket.data.mode = null;
    if (sessionId && sessions.has(sessionId)) {
      const s = sessions.get(sessionId);
      s.mode = null;
      s.room = null;
    }
  });

  socket.on('exit-session', () => {
    if (socket.data.mode === 'pair') handleStrangerLeave(socket, false);
    const idx = waitingQueue.indexOf(socket.id);
    if (idx !== -1) waitingQueue.splice(idx, 1);
    if (sessionId && sessions.has(sessionId)) {
      const sess = sessions.get(sessionId);
      if (sess.disconnectTimer) clearTimeout(sess.disconnectTimer);
      sessions.delete(sessionId);
    }
    currentRoom = null; socket.data.mode = null; socket.data.room = null;
    socketRateLimits.delete(socket.id);
  });

  socket.on('message', async (data) => {
    if (await isBanned(ip)) { socket.emit('banned', await getBan(ip)); socket.disconnect(true); return; }
    if (!checkMsgRate(socket.id)) { socket.emit('system', 'sending too fast, slow down'); return; }
    const room = socket.data.room;
    if (!room) return;
    const rawText = (data.text || '').toString();
    const image = (typeof data.image === 'string' && (data.image.startsWith('/uploads/') || (data.image.startsWith('https://media') && data.image.includes('.giphy.com')))) ? data.image.slice(0,300) : null;

    if (detectSevere(rawText)) {
      await instantPermanentBan(ip, 'severe content: ' + rawText.slice(0, 100));
      await logMessage({ ip, nickname: socket.data.nickname, text: rawText.slice(0, 500), time: Date.now(), flagged: 'severe' });
      socket.emit('banned', { permanent: true, severe: true });
      socket.disconnect(true);
      return;
    }

    if (detectThreat(rawText)) {
      const result = await recordOffense(ip);
      await logMessage({ ip, nickname: socket.data.nickname, text: rawText.slice(0, 500), time: Date.now(), flagged: 'threat' });
      if (result.action === 'warn') {
        socket.emit('moderation-warning', { message: 'That message violates our rules around threats of violence. This is a warning - a second violation will result in a ban.' });
      } else {
        socket.emit('banned', { bannedUntil: result.until, permanent: result.permanent });
        socket.disconnect(true);
      }
      return;
    }

    const text = sanitize(rawText);
    if (!text && !image) return;
    const msg = {
      id: crypto.randomBytes(6).toString('hex'),
      nickname: socket.data.nickname,
      text, image,
      time: Date.now()
    };
    logMessage({ ip, nickname: socket.data.nickname, text: text.slice(0, 500), image, time: Date.now(), flagged: null });
    await trackMessage();
    socket.to(room).emit('message', { ...msg, mine: false });
    socket.emit('message', { ...msg, mine: true });
  });

  socket.on('typing', () => {
    const room = socket.data.room;
    if (room) socket.to(room).emit('typing');
  });

  socket.on('disconnect', () => {
    socketRateLimits.delete(socket.id);
    const idx = waitingQueue.indexOf(socket.id);
    if (idx !== -1) waitingQueue.splice(idx, 1);
    if (!sessionId || !sessions.has(sessionId)) return;
    const sess = sessions.get(sessionId);
    sess.socketId = null;
    sess.disconnectTimer = setTimeout(() => {
      if (sess.mode === 'pair') {
        const partnerSid = clearPairing(sessionId);
        if (partnerSid) {
          const ps = sessions.get(partnerSid);
          if (ps && ps.socketId) {
            const psock = io.sockets.sockets.get(ps.socketId);
            if (psock) {
              psock.emit('stranger-left');
              if (sess.room) psock.leave(sess.room);
              psock.data.mode = null;
              psock.data.room = null;
            }
          }
          if (ps) { ps.mode = null; ps.room = null; }
        }
      }
      sessions.delete(sessionId);
    }, GRACE_MS);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('AnonyChat running on port ' + PORT));
