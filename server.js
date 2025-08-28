// server.js
import express from "express";
import http from "http";
import path from "path";
import fs from "fs";

import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import { Server } from "socket.io";
import { nanoid } from "nanoid";
import { fileURLToPath } from "url";

// Fix for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const DB_FILE = path.join(__dirname, 'db.json');
const JWT_SECRET = process.env.JWT_SECRET || 'please_change_secret_in_prod';

// --- tiny JSON DB helpers ---
function ensureDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = { users: [], rooms: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
  }
}
function readDB() {
  ensureDB();
  return JSON.parse(fs.readFileSync(DB_FILE));
}
function writeDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
function getUserByEmail(email) {
  const db = readDB();
  return db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
}
function getUserById(id) {
  const db = readDB();
  return db.users.find(u => u.id === id);
}
function saveUser(user) {
  const db = readDB();
  db.users = db.users.filter(u => u.id !== user.id);
  db.users.push(user);
  writeDB(db);
}

// --- express + http server ---
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- auth middleware for REST ---
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Missing Authorization' });
  const token = header.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// --- REST APIs ---
// POST /api/register { name, email, password }
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'name,email,password required' });
  if (getUserByEmail(email)) return res.status(400).json({ error: 'Email already registered' });

  const id = nanoid(8);
  const passwordHash = bcrypt.hashSync(password, 10);
  const user = { id, name, email: email.toLowerCase(), passwordHash, createdAt: new Date().toISOString(), online: false };
  const db = readDB();
  db.users.push(user);
  writeDB(db);

  const token = jwt.sign({ userId: id, name }, JWT_SECRET, { expiresIn: '7d' });
  return res.json({ token, user: { id, name, email: user.email } });
});

// POST /api/login { email, password }
app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email,password required' });
  const user = getUserByEmail(email);
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  if (!bcrypt.compareSync(password, user.passwordHash)) return res.status(400).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ userId: user.id, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
  return res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

// GET /api/me
app.get('/api/me', authMiddleware, (req, res) => {
  const user = getUserById(req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, name: user.name, email: user.email, online: user.online });
});

// POST /api/rooms -> create new room code
app.post('/api/rooms', authMiddleware, (req, res) => {
  const code = nanoid(6).toUpperCase();
  const db = readDB();
  db.rooms.push({ code, owner: req.user.userId, createdAt: new Date().toISOString() });
  writeDB(db);
  return res.json({ code });
});

// GET /api/rooms/:code -> check exists
app.get('/api/rooms/:code', authMiddleware, (req, res) => {
  const code = req.params.code.toUpperCase();
  const db = readDB();
  const room = db.rooms.find(r => r.code === code);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  res.json({ code: room.code, owner: room.owner, createdAt: room.createdAt });
});

// GET /api/users/online -> list online users
app.get('/api/users/online', authMiddleware, (req, res) => {
  const db = readDB();
  const online = db.users.filter(u => u.online && u.id !== req.user.userId)
    .map(u => ({ id: u.id, name: u.name, email: u.email }));
  res.json({ users: online });
});

// --- HTTP Server + Socket.IO for signaling ---
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

// in-memory maps
const userSocketMap = {};    // userId -> socketId
const socketUserMap = {};    // socketId -> userId
const pendingMatches = {};   // targetUserId -> fromUserId

// socket auth middleware
io.use((socket, next) => {
  // client should send token either as socket.handshake.auth.token
  const token = (socket.handshake.auth && socket.handshake.auth.token) || socket.handshake.query?.token;
  if (!token) return next(new Error('Authentication error: no token'));
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    socket.user = payload; // { userId, name, iat, exp }
    next();
  } catch (err) {
    next(new Error('Authentication error: invalid token'));
  }
});

io.on('connection', socket => {
  const userId = socket.user.userId;
  console.log('Socket connected', socket.id, 'user', userId);

  // mark online
  userSocketMap[userId] = socket.id;
  socketUserMap[socket.id] = userId;
  const db1 = readDB();
  const uidx = db1.users.findIndex(u => u.id === userId);
  if (uidx !== -1) { db1.users[uidx].online = true; db1.users[uidx].lastSeen = new Date().toISOString(); writeDB(db1); }

  // --- Random-match flow ---
  socket.on('request-random', () => {
    // find random other online user
    const db = readDB();
    const candidates = db.users.filter(u => u.online && u.id !== userId);
    if (!candidates.length) {
      socket.emit('no-match', { message: 'No users online right now' });
      return;
    }
    const target = candidates[Math.floor(Math.random() * candidates.length)];
    pendingMatches[target.id] = userId; // target has request from userId
    const targetSocket = userSocketMap[target.id];
    if (targetSocket) {
      io.to(targetSocket).emit('incoming-request', { from: userId, fromName: socket.user.name });
      socket.emit('request-sent', { to: target.id, toName: target.name });
    } else {
      socket.emit('no-match', { message: 'Chosen user is not reachable' });
    }
  });

  // target can accept a request: { fromUserId }
  socket.on('accept-request', ({ fromUserId }) => {
    // check pending
    if (pendingMatches[userId] !== fromUserId) {
      socket.emit('no-pending', { message: 'No matching request found' });
      return;
    }
    // create a room for the pair
    const roomCode = nanoid(6).toUpperCase();
    const db = readDB();
    db.rooms.push({ code: roomCode, owner: fromUserId, createdAt: new Date().toISOString() });
    writeDB(db);

    // notify both participants to start the call (they will navigate to room)
    const requesterSocket = userSocketMap[fromUserId];
    const targetSocket = socket.id;
    io.to(requesterSocket).emit('match-start', { roomCode, other: { id: userId, name: getUserName(userId) } });
    io.to(targetSocket).emit('match-start', { roomCode, other: { id: fromUserId, name: getUserName(fromUserId) } });

    delete pendingMatches[userId];
  });

  socket.on('decline-request', ({ fromUserId }) => {
    if (pendingMatches[userId] === fromUserId) delete pendingMatches[userId];
    const requesterSocket = userSocketMap[fromUserId];
    if (requesterSocket) io.to(requesterSocket).emit('request-declined', { by: userId });
  });

  // --- Room / signaling ---
  socket.on('join-room', (room) => {
    try {
      // list of socket ids already inside room
      const clients = io.sockets.adapter.rooms.get(room) || new Set();
      const existingClients = [...clients]; // before join
      socket.join(room);
      // tell the joining socket who is already in the room
      socket.emit('existing-users', existingClients);
      // notify others
      socket.to(room).emit('user-joined', socket.id);
      console.log(`User ${socket.id} joined room ${room}`);
    } catch (e) {
      console.error('join-room error', e);
    }
  });

  // forward offer to a specific socket id
  socket.on('offer', ({ target, sdp }) => {
    if (!target) return;
    io.to(target).emit('offer', { from: socket.id, sdp });
  });

  // forward answer to a specific socket id
  socket.on('answer', ({ target, sdp }) => {
    if (!target) return;
    io.to(target).emit('answer', { from: socket.id, sdp });
  });

  // forward ice candidate to specific socket id
  socket.on('ice-candidate', ({ target, candidate }) => {
    if (!target) return;
    io.to(target).emit('ice-candidate', { from: socket.id, candidate });
  });

  // leave room
  socket.on('leave-room', (room) => {
    try {
      socket.leave(room);
      socket.to(room).emit('user-left', socket.id);
    } catch (e) {}
  });

  // when socket disconnects
  socket.on('disconnecting', () => {
    console.log('disconnecting', socket.id);
    for (const room of socket.rooms) {
      if (room !== socket.id) socket.to(room).emit('user-left', socket.id);
    }
  });

  socket.on('disconnect', () => {
    console.log('Socket disconnected', socket.id);
    // cleanup
    const uid = socketUserMap[socket.id];
    if (uid) {
      delete userSocketMap[uid];
      delete socketUserMap[socket.id];
      const db = readDB();
      const idx = db.users.findIndex(u => u.id === uid);
      if (idx !== -1) { db.users[idx].online = false; db.users[idx].lastSeen = new Date().toISOString(); writeDB(db); }
    }
  });
});

// helper to find name
function getUserName(userId) {
  const u = getUserById(userId);
  return u ? u.name : 'Unknown';
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));
