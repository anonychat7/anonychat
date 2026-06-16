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
app.use('/socket.io', rateLimit({ windowMs: 60*1000, max: 120 }));

const io = new Server(server, {
  maxHttpBufferSize: 2e6,
  cors: { origin: false },
  pingTimeout: 20000,
  pingInterval: 25000,
});

const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const IMAGE_SIGNATURES = [
  [0xFF,0xD8,0xFF],
  [0x89,0x50,0x4E,0x47],
  [0x47,0x49,0x46],
  [0x52,0x49,0x46,0x46],
];

function isRealImage(buffer) {
  return IMAGE_SIGNATURES.some(sig => sig.every((byte,i) => buffer[i] === byte));
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

app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1d', etag: true }));

app.post('/upload', (req, res) => {
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

const rooms = new Map();
const messagesById = new Map();
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

const GLOBAL_ROOM = 'lobby';

function getRoom(id) {
  if (!rooms.has(id)) rooms.set(id, { users: new Map(), messages: [] });
  return rooms.get(id);
}

function pairRoomId(a, b) { return 'pair_' + [a,b].sort().join('_'); }

function removeUserFromRoom(roomId, nickname, oldSocketId) {
  if (!roomId) return;
  const room = getRoom(roomId);
  if (oldSocketId) {
    room.users.delete(oldSocketId);
  } else {
    for (const [sid, nick] of room.users.entries()) {
      if (nick === nickname) { room.users.delete(sid); break; }
    }
  }
}

function leaveCurrentRoom(socket, nickname, currentRoom) {
  if (!currentRoom) return;
  const room = getRoom(currentRoom);
  room.users.delete(socket.id);
  socket.leave(currentRoom);
  io.to(currentRoom).emit('system', nickname + ' left the chat');
  io.to(currentRoom).emit('presence', room.users.size);
}

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

setInterval(() => {
  const cutoff = Date.now() - 24*60*60*1000;
  for (const [id, entry] of messagesById.entries()) {
    if (entry.msg.time < cutoff) messagesById.delete(id);
  }
  for (const [id, room] of rooms.entries()) {
    if (room.users.size === 0 && id !== GLOBAL_ROOM) rooms.delete(id);
  }
}, 10*60*1000);

setInterval(() => {}, 1000*60*14);

io.on('connection', (socket) => {
  let nickname = randomName();
  let currentRoom = null;
  let sessionId = null;
  let resumed = false;

  socket.on('resume-session', (sid) => {
    if (sid && (typeof sid !== 'string' || sid.length > 64)) return;

    if (sid && sessions.has(sid)) {
      const sess = sessions.get(sid);
      if (sess.disconnectTimer) { clearTimeout(sess.disconnectTimer); sess.disconnectTimer = null; }
      if (sess.room && sess.mode === 'room') removeUserFromRoom(sess.room, sess.nickname, sess.socketId);

      sessionId = sid;
      nickname = sess.nickname;
      const oldSocketId = sess.socketId;
      sess.socketId = socket.id;
      socket.data.nickname = nickname;
      socket.data.sessionId = sessionId;

      if (sess.mode === 'room' && sess.room) {
        currentRoom = sess.room;
        socket.join(currentRoom);
        socket.data.room = currentRoom;
        socket.data.mode = 'room';
        const room = getRoom(currentRoom);
        room.users.delete(oldSocketId);
        room.users.set(socket.id, nickname);
        socket.emit('joined', { nickname, room: currentRoom, mode: 'room', history: room.messages.slice(-50), resumed: true });
        io.to(currentRoom).emit('presence', room.users.size);
        resumed = true;
      } else if (sess.mode === 'pair' && sess.room) {
        const partnerSid = pairings.get(sessionId);
        const partnerSess = partnerSid ? sessions.get(partnerSid) : null;
        if (partnerSess && partnerSess.socketId) {
          currentRoom = sess.room;
          socket.join(currentRoom);
          socket.data.room = currentRoom;
          socket.data.mode = 'pair';
          socket.emit('joined', { nickname, room: 'stranger', mode: 'pair', history: [], resumed: true });
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

  socket.on('join', (roomId) => {
    if (typeof roomId !== 'string') return;
    const target = roomId.trim() ? roomId.trim().toLowerCase().replace(/[^a-z0-9-]/g,'').slice(0,32) : GLOBAL_ROOM;
    leaveCurrentRoom(socket, nickname, currentRoom);
    currentRoom = target || GLOBAL_ROOM;
    socket.join(currentRoom);
    socket.data.room = currentRoom;
    socket.data.mode = 'room';
    const room = getRoom(currentRoom);
    room.users.set(socket.id, nickname);
    if (sessionId && sessions.has(sessionId)) { const s = sessions.get(sessionId); s.mode = 'room'; s.room = currentRoom; }
    socket.emit('joined', { nickname, room: currentRoom, mode: 'room', history: room.messages.slice(-50) });
    io.to(currentRoom).emit('system', nickname + ' joined the chat');
    io.to(currentRoom).emit('presence', room.users.size);
  });

  socket.on('find-stranger', () => {
    leaveCurrentRoom(socket, nickname, currentRoom);
    currentRoom = null;
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
      socket.emit('joined', { nickname, room: 'stranger', mode: 'pair', history: [] });
      partnerSocket.emit('joined', { nickname: partnerSocket.data.nickname, room: 'stranger', mode: 'pair', history: [] });
      io.to(roomId).emit('system', 'connected to a stranger. say hi!');
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

  socket.on('exit-session', () => {
    if (socket.data.mode === 'pair') {
      handleStrangerLeave(socket, false);
    } else if (socket.data.mode === 'room' && currentRoom) {
      const room = getRoom(currentRoom);
      room.users.delete(socket.id);
      io.to(currentRoom).emit('system', nickname + ' left the chat');
      io.to(currentRoom).emit('presence', room.users.size);
      socket.leave(currentRoom);
    }
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
    if (!checkMsgRate(socket.id)) { socket.emit('system', 'you are sending too fast. slow down.'); return; }
    const room = socket.data.room;
    if (!room) return;
    const text = sanitize(data.text || '');
    const image = (typeof data.image === 'string' && data.image.startsWith('/uploads/')) ? data.image.slice(0,200) : null;
    if (!text && !image) return;
    const msg = {
      id: crypto.randomBytes(6).toString('hex'),
      from: nickname, text, image,
      time: Date.now(), reactions: {}
    };
    messagesById.set(msg.id, { roomId: room, msg });
    if (socket.data.mode === 'room') {
      const r = getRoom(room);
      r.messages.push(msg);
      if (r.messages.length > 200) r.messages.shift();
    }
    io.to(room).emit('message', msg);
  });

  socket.on('reaction', ({ id, emoji }) => {
    if (typeof id !== 'string' || typeof emoji !== 'string' || emoji.length > 8) return;
    const entry = messagesById.get(id);
    if (!entry) return;
    const { roomId, msg } = entry;
    if (!msg.reactions[emoji]) msg.reactions[emoji] = new Set();
    if (msg.reactions[emoji].has(socket.id)) {
      msg.reactions[emoji].delete(socket.id);
      if (msg.reactions[emoji].size === 0) delete msg.reactions[emoji];
    } else {
      msg.reactions[emoji].add(socket.id);
    }
    const counts = {};
    for (const [e, set] of Object.entries(msg.reactions)) counts[e] = set.size;
    io.to(roomId).emit('reaction-update', { id, counts });
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
      } else if (sess.mode === 'room' && sess.room) {
        const room = getRoom(sess.room);
        for (const [sockId, nick] of room.users.entries()) {
          if (nick === sess.nickname && !io.sockets.sockets.get(sockId)) room.users.delete(sockId);
        }
        io.to(sess.room).emit('system', sess.nickname + ' left the chat');
        io.to(sess.room).emit('presence', room.users.size);
      }
      sessions.delete(sessionId);
    }, GRACE_MS);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('AnonyChat running on port ' + PORT));
