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

const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'", "ws:", "wss:"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
    }
  }
}));

const limiter = rateLimit({ windowMs: 60*1000, max: 60, message: { error: 'Too many requests.' } });
app.use('/upload', limiter);

const io = new Server(server, {
  maxHttpBufferSize: 2e6,
  cors: { origin: false },
  pingTimeout: 20000,
  pingInterval: 25000,
});

const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const BANS_FILE = path.join(__dirname, 'bans.json');

function loadBans() {
  try { return JSON.parse(fs.readFileSync(BANS_FILE, 'utf8')); } catch { return {}; }
}
function saveBans(bans) {
  try { fs.writeFileSync(BANS_FILE, JSON.stringify(bans)); } catch (e) { console.error('ban save failed', e); }
}
let bans = loadBans();

function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function isBanned(ip) {
  const rec = bans[ip];
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

function recordOffense(ip) {
  if (!bans[ip]) bans[ip] = { offenses: 0, bannedUntil: 0, warned: false };
  const rec = bans[ip];
  rec.offenses += 1;
  if (rec.offenses === 1) {
    rec.warned = true;
    saveBans(bans);
    return { action: 'warn' };
  }
  const duration = banDurationForOffense(rec.offenses);
  rec.bannedUntil = duration ? Date.now() + duration : null;
  saveBans(bans);
  return { action: 'ban', permanent: duration === null, until: rec.bannedUntil };
}

const THREAT_PATTERNS = [
  /\bi\s*(?:will|'?ll|am going to|gonna)\s*(?:kill|murder|stab|shoot|hurt|beat|rape)\s*(?:you|him|her|them|u)\b/i,
  /\bkill\s*(?:yourself|urself|ur ?self)\b/i,
  /\bkys\b/i,
  /\bi\s*(?:will|'?ll)\s*(?:find|hunt)\s*you\s*(?:down)?\s*and\s*(?:kill|hurt|kill you)\b/i,
  /\bgonna\s*shoot\s*up\b/i,
  /\bi\s*(?:will|'?ll)\s*bomb\b/i,
  /\bhow\s*to\s*(?:make|build)\s*a\s*bomb\b/i,
  /\bhow\s*to\s*kill\s*(?:someone|a person|people)\b/i,
];

function detectThreat(text) {
  return THREAT_PATTERNS.some(p => p.test(text));
}

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

app.post('/upload', (req, res) => {
  const ip = getClientIp(req);
  if (isBanned(ip)) return res.status(403).json({ error: 'banned' });
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

const waitingQueue = [];
const pairings = new Map();
const sessions = new Map();
const socketRateLimits = new Map();
const GRACE_MS = 45000;
const MSG_RATE_LIMIT = 20;
const MSG_RATE_WINDOW = 10000;

const adjectives = ['Mysterious','Silent','Curious','Hidden','Lone','Shadow','Quiet','Wandering','Unknown','Masked','Drifting','Nameless','Cryptic','Phantom','Velvet'];
const nouns = ['Fox','Owl','Wolf','Raven','Tiger','Ghost','Falcon','Panther','Cobra','Eagle','Lynx','Otter','Hawk','Crow','Stag'];

function randomName() {
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
    if (!candidateSocket || candidateId === socket.id) { waitingQueue.shift(); continue; }
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

io.use((socket, next) => {
  const ip = getClientIp(socket.request);
  socket.data.ip = ip;
  if (isBanned(ip)) return next(new Error('banned'));
  next();
});

io.on('connection', (socket) => {
  let nickname = randomName();
  let currentRoom = null;
  let sessionId = null;
  let resumed = false;
  const ip = socket.data.ip;

  socket.on('resume-session', (sid) => {
    if (isBanned(ip)) { socket.emit('banned', bans[ip]); socket.disconnect(true); return; }
    if (sid && (typeof sid !== 'string' || sid.length > 64)) return;

    if (sid && sessions.has(sid)) {
      const sess = sessions.get(sid);
      if (sess.disconnectTimer) { clearTimeout(sess.disconnectTimer); sess.disconnectTimer = null; }
      sessionId = sid;
      nickname = sess.nickname;
      sess.socketId = socket.id;
      socket.data.nickname = nickname;
      socket.data.sessionId = sessionId;

      if (sess.mode === 'pair' && sess.room) {
        const partnerSid = pairings.get(sessionId);
        const partnerSess = partnerSid ? sessions.get(partnerSid) : null;
        if (partnerSess && partnerSess.socketId) {
          currentRoom = sess.room;
          socket.join(currentRoom);
          socket.data.room = currentRoom;
          socket.data.mode = 'pair';
          socket.emit('joined', { nickname, mode: 'pair', resumed: true });
          io.to(currentRoom).emit('presence', 2);
          resumed = true;
        } else {
          sessions.delete(sessionId);
          sessionId = null;
        }
      } else {
        sessions.delete(sessionId);
        sessionId = null;
      }
    }

    if (!resumed) {
      sessionId = sid || crypto.randomBytes(8).toString('hex');
      sessions.set(sessionId, { nickname, mode: null, room: null, socketId: socket.id, disconnectTimer: null });
      socket.data.nickname = nickname;
      socket.data.sessionId = sessionId;
      socket.emit('session', { sessionId, nickname });
    }
  });

  socket.on('find-stranger', () => {
    if (isBanned(ip)) { socket.emit('banned', bans[ip]); socket.disconnect(true); return; }
    if (currentRoom) { socket.leave(currentRoom); currentRoom = null; }
    socket.data.mode = 'matching';

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
      socket.emit('joined', { nickname, mode: 'pair' });
      partnerSocket.emit('joined', { nickname: partnerSocket.data.nickname, mode: 'pair' });
      io.to(roomId).emit('system', 'stranger connected');
      io.to(roomId).emit('presence', 2);
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
        if (ps) { ps.emit('stranger-left'); ps.leave(roomId); ps.data.mode = null; ps.data.room = null; }
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
  });

  socket.on('exit-session', () => {
    if (socket.data.mode === 'pair') handleStrangerLeave(socket, false);
    if (sessionId && sessions.has(sessionId)) {
      const sess = sessions.get(sessionId);
      if (sess.disconnectTimer) clearTimeout(sess.disconnectTimer);
      sessions.delete(sessionId);
    }
    const idx = waitingQueue.indexOf(socket.id);
    if (idx !== -1) waitingQueue.splice(idx, 1);
    currentRoom = null; socket.data.mode = null; socket.data.room = null;
    socketRateLimits.delete(socket.id);
  });

  socket.on('message', (data) => {
    if (isBanned(ip)) { socket.emit('banned', bans[ip]); socket.disconnect(true); return; }
    if (!checkMsgRate(socket.id)) { socket.emit('system', 'sending too fast, slow down'); return; }
    const room = socket.data.room;
    if (!room) return;
    const rawText = (data.text || '').toString();
    const image = (typeof data.image === 'string' && data.image.startsWith('/uploads/')) ? data.image.slice(0,200) : null;

    if (detectThreat(rawText)) {
      const result = recordOffense(ip);
      if (result.action === 'warn') {
        socket.emit('moderation-warning', { message: 'That message violates our rules around threats of violence. This is a warning - a second violation will result in a ban.' });
      } else {
        socket.emit('banned', { offenses: bans[ip].offenses, bannedUntil: result.until, permanent: result.permanent });
        socket.disconnect(true);
      }
      return;
    }

    const text = sanitize(rawText);
    if (!text && !image) return;
    const msg = {
      id: crypto.randomBytes(6).toString('hex'),
      from: nickname, text, image,
      time: Date.now()
    };
    io.to(room).emit('message', msg);
  });

  socket.on('typing', () => {
    const room = socket.data.room;
    if (room) socket.to(room).emit('typing', nickname);
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
            if (psock) { psock.emit('stranger-left'); if (sess.room) psock.leave(sess.room); psock.data.mode = null; psock.data.room = null; }
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
