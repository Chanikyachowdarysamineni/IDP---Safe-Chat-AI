require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const http = require('http');
const { Server: IOServer } = require('socket.io');

const User = require('./models/user');
const Profile = require('./models/profile');
const Message = require('./models/message');
const ModerationAction = require('./models/moderation_action');
const Annotation = require('./models/annotation');
const Conversation = require('./models/conversation');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || process.env.DB_URI || 'mongodb://localhost:27017/emotion-shield';
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Helpers - auth middleware (moved up so routes can reference it)
const authMiddleware = async (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing token' });
  const token = auth.replace('Bearer ', '');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Create HTTP server and Socket.IO server for realtime
const server = http.createServer(app);
const io = new IOServer(server, {
  cors: {
    origin: '*',
  }
});

io.use((socket, next) => {
  // Authenticate socket connections using JWT passed in auth token
  try {
    const token = socket.handshake.auth && socket.handshake.auth.token;
    if (!token) return next();
    const payload = jwt.verify(token, JWT_SECRET);
    socket.userId = payload.id;
    // join a user-specific room for direct notifications
    socket.join(`user:${socket.userId}`);
    return next();
  } catch (err) {
    // allow unauthenticated sockets but not attach userId
    return next();
  }
});

io.on('connection', (socket) => {
  console.log('socket connected', socket.id);

  // track online counts per user for presence
  if (!global.onlineUsers) global.onlineUsers = {};
  if (socket.userId) {
    global.onlineUsers[socket.userId] = (global.onlineUsers[socket.userId] || 0) + 1;
    // notify conversation rooms the user is online
    (async () => {
      try {
        const convs = await Conversation.find({ participant_ids: socket.userId }).lean();
        for (const c of convs) {
          io.to(`conversation:${c.id}`).emit('presence', { user_id: socket.userId, online: true });
        }
      } catch (e) {
        console.warn('presence notify error', e);
      }
    })();
  }

  // join a conversation room (server will verify membership)
  socket.on('join_conversation', async (convId) => {
    try {
      if (!socket.userId) return;
      const conv = await Conversation.findOne({ id: convId }).lean();
      if (!conv) return;
      if (!Array.isArray(conv.participant_ids) || !conv.participant_ids.includes(socket.userId)) return;
      socket.join(`conversation:${convId}`);
    } catch (err) {
      console.warn('join_conversation error', err);
    }
  });

  socket.on('leave_conversation', (convId) => {
    try {
      socket.leave(`conversation:${convId}`);
    } catch (err) {}
  });

  // Client can send messages over socket; server validates and persists
  socket.on('send_message', async (payload) => {
    try {
      if (!socket.userId) return socket.emit('error', { error: 'unauthorized' });
      const { conversation_id, recipient_id, content, is_abusive, abuse_score, abuse_type, severity, emotions, ciphertext, nonce, sender_pubkey, client_temp_id } = payload || {};
      let convoId = conversation_id || null;
      if (convoId) {
        // verify sender is a participant of the provided conversation
        const convCheck = await Conversation.findOne({ id: convoId }).lean();
        if (!convCheck) return socket.emit('error', { error: 'conversation_not_found' });
        if (!Array.isArray(convCheck.participant_ids) || !convCheck.participant_ids.includes(socket.userId)) return socket.emit('error', { error: 'forbidden' });
      }
      if (!convoId && recipient_id) {
        const ids = [socket.userId, recipient_id].sort();
        let convo = await Conversation.findOne({ participant_ids: ids }).lean();
        if (!convo) {
          convo = await Conversation.create({ id: uuidv4(), participant_ids: ids, created_at: new Date().toISOString(), last_message_at: new Date().toISOString() });
        } else {
          await Conversation.findOneAndUpdate({ id: convo.id }, { last_message_at: new Date().toISOString() });
        }
        convoId = convo.id;
      }

      // Allow either E2EE encrypted payload or plaintext 'content' (server will store plaintext only if provided)
      if (!content && (!ciphertext || !nonce || !sender_pubkey)) {
        return socket.emit('error', { error: 'missing_encrypted_payload_or_content' });
      }

      // accept client-side analysis metadata (client-side moderation) when provided
      const msgData = {
        id: uuidv4(),
        client_temp_id: client_temp_id || null,
        // if client provided plaintext content we store it; otherwise keep null to honor E2EE
        content: content || null,
        ciphertext: ciphertext || null,
        nonce: nonce || null,
        sender_pubkey: sender_pubkey || null,
        user_id: socket.userId,
        recipient_id: recipient_id || null,
        conversation_id: convoId,
        created_at: new Date().toISOString(),
        is_abusive: !!is_abusive,
        abuse_score: typeof abuse_score === 'number' ? abuse_score : 0,
        abuse_type: abuse_type || null,
        severity: severity || 'safe',
        emotions: Array.isArray(emotions) ? emotions : []
      };

      const message = await Message.create(msgData);

      // populate profile
      const profile = await Profile.findOne({ user_id: message.user_id }).lean();
  const payloadOut = { ...message.toObject ? message.toObject() : message, profiles: profile || { username: 'Unknown' } };

      if (convoId) {
        io.to(`conversation:${convoId}`).emit('message', payloadOut);
      } else if (recipient_id) {
        io.to(`user:${recipient_id}`).emit('message', payloadOut);
      } else {
        io.to('global').emit('message', payloadOut);
      }

      // Acknowledge to sender with mapping to client_temp_id so frontend can reconcile optimistic UI
      socket.emit('message_sent', { data: message, client_temp_id: message.client_temp_id || null });
    } catch (err) {
      console.error('send_message error', err);
      socket.emit('error', { error: 'failed_to_send' });
    }
  });

  // Clear conversation request from a client: delete messages server-side and notify room
  socket.on('clear_conversation', async ({ conversation_id }) => {
    try {
      if (!socket.userId) return;
      if (!conversation_id) return;
      const conv = await Conversation.findOne({ id: conversation_id }).lean();
      if (!conv) return;
      // Only participants may clear a conversation
      if (!Array.isArray(conv.participant_ids) || !conv.participant_ids.includes(socket.userId)) return;

      // Delete messages for the conversation
      await Message.deleteMany({ conversation_id: conversation_id });

      // Optionally update conversation metadata
      await Conversation.findOneAndUpdate({ id: conversation_id }, { last_message_at: new Date().toISOString() });

      // Broadcast to conversation room that it was cleared
      io.to(`conversation:${conversation_id}`).emit('conversation_cleared', { conversation_id });

      // Also notify participants individually (in case they are listening on user rooms)
      for (const pid of conv.participant_ids || []) {
        io.to(`user:${pid}`).emit('conversation_cleared', { conversation_id });
      }
    } catch (err) {
      console.warn('clear_conversation error', err);
    }
  });

  socket.on('disconnect', () => {
    try {
      if (socket.userId && global.onlineUsers && global.onlineUsers[socket.userId]) {
        global.onlineUsers[socket.userId] = Math.max(0, global.onlineUsers[socket.userId] - 1);
        if (global.onlineUsers[socket.userId] === 0) {
          // user went offline
          (async () => {
            try {
              const convs = await Conversation.find({ participant_ids: socket.userId }).lean();
              for (const c of convs) {
                io.to(`conversation:${c.id}`).emit('presence', { user_id: socket.userId, online: false });
              }
            } catch (e) {
              console.warn('presence offline notify error', e);
            }
          })();
        }
      }
    } catch (e) {
      /* ignore */
    }
  });
});

// Read receipt via socket: client notifies server when message displayed/decrypted
io.on && io.of && io.of('/');
io.on('connection', () => {}); // ensure io is initialized

// handle message_read from sockets
io.on('connection', (socket) => {
  socket.on('message_read', async ({ message_id }) => {
    try {
      if (!socket.userId) return;
      const msg = await Message.findOne({ id: message_id }).lean();
      if (!msg) return;
      // avoid duplicate entries
      const already = Array.isArray(msg.read_by) && msg.read_by.some(r => r.user_id === socket.userId);
      if (!already) {
        await Message.findOneAndUpdate({ id: message_id }, { $push: { read_by: { user_id: socket.userId, read_at: new Date().toISOString() } } });
      }
      // notify conversation room
      const convId = msg.conversation_id;
      io.to(`conversation:${convId}`).emit('message_read', { message_id, user_id: socket.userId, read_at: new Date().toISOString() });
    } catch (err) {
      console.warn('message_read error', err);
    }
  });
});

// Presence endpoint
app.get('/api/presence/:id', async (req, res) => {
  const id = req.params.id;
  const online = !!(global.onlineUsers && global.onlineUsers[id]);
  res.json({ user_id: id, online });
});

// Mark message as read via REST (optional)
app.post('/api/messages/:id/read', authMiddleware, async (req, res) => {
  const messageId = req.params.id;
  try {
    const msg = await Message.findOne({ id: messageId }).lean();
    if (!msg) return res.status(404).json({ error: 'not found' });
    // ensure requester is a participant
    if (msg.conversation_id) {
      const conv = await Conversation.findOne({ id: msg.conversation_id }).lean();
      if (!conv || !conv.participant_ids.includes(req.user.id)) return res.status(403).json({ error: 'forbidden' });
    } else if (msg.user_id !== req.user.id && msg.recipient_id !== req.user.id) {
      return res.status(403).json({ error: 'forbidden' });
    }
    const already = Array.isArray(msg.read_by) && msg.read_by.some(r => r.user_id === req.user.id);
    if (!already) await Message.findOneAndUpdate({ id: messageId }, { $push: { read_by: { user_id: req.user.id, read_at: new Date().toISOString() } } });
    res.json({ ok: true });
  } catch (err) {
    console.error('mark read error', err);
    res.status(500).json({ error: 'failed' });
  }
});



app.get('/api/health', (req, res) => res.json({ ok: true }));

// Auth
app.post('/api/auth/signup', async (req, res) => {
  const { email, password, username } = req.body;
  if (!email || !password || !username) return res.status(400).json({ error: 'missing fields' });
  const existing = await User.findOne({ email });
  if (existing) return res.status(400).json({ error: 'user exists' });
  const hash = await bcrypt.hash(password, 10);
  const user = await User.create({ id: uuidv4(), email, passwordHash: hash });
  await Profile.create({ user_id: user.id, username, created_at: new Date().toISOString() });
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, email: user.email } });
});

app.post('/api/auth/signin', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: 'invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(400).json({ error: 'invalid credentials' });
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, email: user.email } });
});

app.get('/api/auth/session', authMiddleware, async (req, res) => {
  const user = await User.findOne({ id: req.user.id });
  if (!user) return res.status(404).json({ error: 'not found' });
  res.json({ user: { id: user.id, email: user.email } });
});

// Profiles
app.get('/api/profiles/:id', async (req, res) => {
  const profile = await Profile.findOne({ user_id: req.params.id }).lean();
  res.json({ profile });
});

// list profiles
app.get('/api/profiles', async (req, res) => {
  const profiles = await Profile.find({}).sort({ created_at: -1 }).lean();
  res.json({ data: profiles });
});

app.put('/api/profiles/:id', authMiddleware, async (req, res) => {
  if (req.user.id !== req.params.id) return res.status(403).json({ error: 'forbidden' });
  const { username, public_key } = req.body;
  const update = {};
  if (username) update.username = username;
  if (public_key) update.public_key = public_key;
  await Profile.findOneAndUpdate({ user_id: req.params.id }, update);
  res.json({ ok: true });
});

// Upload or update public key for E2EE
app.post('/api/keys', authMiddleware, async (req, res) => {
  const { public_key } = req.body || {};
  if (!public_key) return res.status(400).json({ error: 'missing public_key' });
  await Profile.findOneAndUpdate({ user_id: req.user.id }, { public_key });
  res.json({ ok: true });
});

// Get a user's public key
app.get('/api/keys/:id', async (req, res) => {
  const profile = await Profile.findOne({ user_id: req.params.id }).lean();
  res.json({ public_key: profile ? profile.public_key : null });
});

// User roles
app.get('/api/user_roles/:id', async (req, res) => {
  const profile = await Profile.findOne({ user_id: req.params.id }).lean();
  const roles = (profile && profile.roles) || ['user'];
  res.json({ roles });
});

// list all user_roles (derived from profiles.roles)
app.get('/api/user_roles', async (req, res) => {
  const profiles = await Profile.find({}).lean();
  const rows = [];
  for (const p of profiles) {
    if (Array.isArray(p.roles)) {
      for (const r of p.roles) {
        rows.push({ user_id: p.user_id, role: r });
      }
    } else {
      rows.push({ user_id: p.user_id, role: 'user' });
    }
  }
  res.json({ data: rows });
});

app.get('/api/admin/has_role', async (req, res) => {
  const { _user_id, _role } = req.query;
  const profile = await Profile.findOne({ user_id: _user_id }).lean();
  const has = profile?.roles?.includes(_role) || false;
  res.json({ has });
});

// Messages
app.get('/api/messages', authMiddleware, async (req, res) => {
  // Only return messages that the authenticated user is a participant of
  const userId = req.user.id;
  const qConversationId = req.query.conversation_id;
  const qUserId = req.query.user_id;

  // If conversation_id is provided, verify membership
  if (qConversationId) {
    const conv = await Conversation.findOne({ id: qConversationId }).lean();
    if (!conv) return res.status(404).json({ error: 'conversation not found' });
    if (!Array.isArray(conv.participant_ids) || !conv.participant_ids.includes(userId)) return res.status(403).json({ error: 'forbidden' });
    const docs = await Message.find({ conversation_id: qConversationId }).sort({ created_at: 1 }).limit(500).lean();
    const userIds = docs.map(d => d.user_id);
    const profiles = await Profile.find({ user_id: { $in: userIds } }).lean();
    const byId = Object.fromEntries(profiles.map(p => [p.user_id, p]));
    const result = docs.map(d => ({ ...d, profiles: byId[d.user_id] || { username: 'Unknown' } }));
    return res.json({ data: result });
  }

  // If user_id is provided, allow only fetching own messages
  if (qUserId) {
    if (qUserId !== userId) return res.status(403).json({ error: 'forbidden' });
    const docs = await Message.find({ user_id: userId }).sort({ created_at: 1 }).limit(500).lean();
    const userIds = docs.map(d => d.user_id);
    const profiles = await Profile.find({ user_id: { $in: userIds } }).lean();
    const byId = Object.fromEntries(profiles.map(p => [p.user_id, p]));
    const result = docs.map(d => ({ ...d, profiles: byId[d.user_id] || { username: 'Unknown' } }));
    return res.json({ data: result });
  }

  // Default: return recent messages involving the user (sent or received or in user's conversations)
  const convs = await Conversation.find({ participant_ids: userId }).lean();
  const convIds = convs.map(c => c.id);
  const docs = await Message.find({ $or: [{ user_id: userId }, { recipient_id: userId }, { conversation_id: { $in: convIds } }] }).sort({ created_at: 1 }).limit(500).lean();
  const userIds = docs.map(d => d.user_id);
  const profiles = await Profile.find({ user_id: { $in: userIds } }).lean();
  const byId = Object.fromEntries(profiles.map(p => [p.user_id, p]));
  const result = docs.map(d => ({ ...d, profiles: byId[d.user_id] || { username: 'Unknown' } }));
  res.json({ data: result });
});

app.post('/api/messages', authMiddleware, async (req, res) => {
  // Accept either encrypted payload (ciphertext, nonce, sender_pubkey) or plaintext 'content'
  const { content, ciphertext, nonce, sender_pubkey, is_abusive, abuse_score, abuse_type, severity, emotions, client_temp_id } = req.body || {};
  // optional recipient or conversation
  const { recipient_id, conversation_id } = req.body || {};
  let convoId = conversation_id || null;
  if (!convoId && recipient_id) {
    // find or create conversation between the two users
    const ids = [req.user.id, recipient_id].sort();
    let convo = await Conversation.findOne({ participant_ids: ids }).lean();
    if (!convo) {
      convo = await Conversation.create({ id: uuidv4(), participant_ids: ids, created_at: new Date().toISOString(), last_message_at: new Date().toISOString() });
    } else {
      await Conversation.findOneAndUpdate({ id: convo.id }, { last_message_at: new Date().toISOString() });
    }
    convoId = convo.id;
  }
  if (!content && (!ciphertext || !nonce || !sender_pubkey)) return res.status(400).json({ error: 'missing_encrypted_payload_or_content' });
  const messagePayload = {
    id: uuidv4(),
    client_temp_id: client_temp_id || null,
    content: content || null,
    ciphertext: ciphertext || null,
    nonce: nonce || null,
    sender_pubkey: sender_pubkey || null,
    user_id: req.user.id,
    recipient_id: recipient_id || null,
    conversation_id: convoId,
    created_at: new Date().toISOString(),
    is_abusive: !!is_abusive,
    abuse_score: typeof abuse_score === 'number' ? abuse_score : 0,
    abuse_type: abuse_type || null,
    severity: severity || 'safe',
    emotions: Array.isArray(emotions) ? emotions : []
  };
  const message = await Message.create(messagePayload);

  // populate profile for emitter
  const profile = await Profile.findOne({ user_id: message.user_id }).lean();
  const payload = { ...message.toObject ? message.toObject() : message, profiles: profile || { username: 'Unknown' } };

  // emit to conversation room or global
  if (convoId) {
    io.to(`conversation:${convoId}`).emit('message', payload);
  } else {
    io.to('global').emit('message', payload);
  }
  res.json({ data: message, client_temp_id: message.client_temp_id || null });
});

// conversations
app.post('/api/conversations', authMiddleware, async (req, res) => {
  const { participant_ids } = req.body || {};
  if (!Array.isArray(participant_ids) || participant_ids.length < 2) return res.status(400).json({ error: 'participant_ids required' });
  // Ensure requester is part of the participants to avoid creating conversations on behalf of others
  if (!participant_ids.includes(req.user.id)) return res.status(403).json({ error: 'forbidden' });
  const ids = participant_ids.slice().sort();
  let convo = await Conversation.findOne({ participant_ids: ids }).lean();
  if (!convo) {
    convo = await Conversation.create({ id: uuidv4(), participant_ids: ids, created_at: new Date().toISOString(), last_message_at: new Date().toISOString() });
  }
  res.json({ data: convo });
});

app.get('/api/conversations', authMiddleware, async (req, res) => {
  // list conversations for authenticated user
  const userId = req.user.id;
  const convos = await Conversation.find({ participant_ids: userId }).sort({ last_message_at: -1 }).lean();
  // attach last message preview
  const result = [];
  for (const c of convos) {
    const lastMsg = await Message.findOne({ conversation_id: c.id }).sort({ created_at: -1 }).lean();
    const otherIds = (c.participant_ids || []).filter(id => id !== userId);
    const profiles = await Profile.find({ user_id: { $in: otherIds } }).lean();
    result.push({ conversation: c, last_message: lastMsg || null, participants: profiles });
  }
  res.json({ data: result });
});

app.get('/api/conversations/:id/messages', authMiddleware, async (req, res) => {
  const convId = req.params.id;
  // verify user is a participant of the conversation
  const conv = await Conversation.findOne({ id: convId }).lean();
  if (!conv) return res.status(404).json({ error: 'conversation not found' });
  if (!Array.isArray(conv.participant_ids) || !conv.participant_ids.includes(req.user.id)) return res.status(403).json({ error: 'forbidden' });
  const msgs = await Message.find({ conversation_id: convId }).sort({ created_at: 1 }).lean();
  const userIds = msgs.map(m => m.user_id);
  const profiles = await Profile.find({ user_id: { $in: userIds } }).lean();
  const byId = Object.fromEntries(profiles.map(p => [p.user_id, p]));
  const result = msgs.map(m => ({ ...m, profiles: byId[m.user_id] || { username: 'Unknown' } }));
  res.json({ data: result });
});

// Delete all messages in a conversation (authorized participants only)
app.delete('/api/conversations/:id/messages', authMiddleware, async (req, res) => {
  const convId = req.params.id;
  try {
    const conv = await Conversation.findOne({ id: convId }).lean();
    if (!conv) return res.status(404).json({ error: 'conversation not found' });
    if (!Array.isArray(conv.participant_ids) || !conv.participant_ids.includes(req.user.id)) return res.status(403).json({ error: 'forbidden' });

    // Delete messages server-side
    await Message.deleteMany({ conversation_id: convId });

    // Update conversation metadata
    await Conversation.findOneAndUpdate({ id: convId }, { last_message_at: new Date().toISOString() });

    // Broadcast to conversation room
    try {
      io.to(`conversation:${convId}`).emit('conversation_cleared', { conversation_id: convId });
      for (const pid of conv.participant_ids || []) {
        io.to(`user:${pid}`).emit('conversation_cleared', { conversation_id: convId });
      }
    } catch (e) {
      console.debug('broadcast conversation_cleared failed', e);
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('delete conversation messages error', err);
    res.status(500).json({ error: 'failed' });
  }
});

app.post('/api/conversations/:id/messages', authMiddleware, async (req, res) => {
  const convId = req.params.id;
  // Expect encrypted payload
  const { content, ciphertext, nonce, sender_pubkey, is_abusive, abuse_score, abuse_type, severity, emotions, client_temp_id } = req.body || {};
  // verify membership
  const conv = await Conversation.findOne({ id: convId }).lean();
  if (!conv) return res.status(404).json({ error: 'conversation not found' });
  if (!Array.isArray(conv.participant_ids) || !conv.participant_ids.includes(req.user.id)) return res.status(403).json({ error: 'forbidden' });
  if (!content && (!ciphertext || !nonce || !sender_pubkey)) return res.status(400).json({ error: 'missing_encrypted_payload_or_content' });
  const messagePayload = {
    id: uuidv4(),
    client_temp_id: client_temp_id || null,
    content: content || null,
    ciphertext: ciphertext || null,
    nonce: nonce || null,
    sender_pubkey: sender_pubkey || null,
    user_id: req.user.id,
    conversation_id: convId,
    created_at: new Date().toISOString(),
    is_abusive: !!is_abusive,
    abuse_score: typeof abuse_score === 'number' ? abuse_score : 0,
    abuse_type: abuse_type || null,
    severity: severity || 'safe',
    emotions: Array.isArray(emotions) ? emotions : []
  };
  const message = await Message.create(messagePayload);
  await Conversation.findOneAndUpdate({ id: convId }, { last_message_at: new Date().toISOString() });
  // attach profile and emit to conversation room
  const profile = await Profile.findOne({ user_id: message.user_id }).lean();
  const payload = { ...message.toObject ? message.toObject() : message, profiles: profile || { username: 'Unknown' } };
  io.to(`conversation:${convId}`).emit('message', payload);
  res.json({ data: message });
});

app.get('/api/messages/flagged', async (req, res) => {
  const docs = await Message.find({ is_abusive: true }).sort({ created_at: -1 }).limit(100).lean();
  const userIds = docs.map(d => d.user_id);
  const profiles = await Profile.find({ user_id: { $in: userIds } }).lean();
  const byId = Object.fromEntries(profiles.map(p => [p.user_id, p]));
  const result = docs.map(d => ({ ...d, profiles: byId[d.user_id] || { username: 'Unknown' } }));
  res.json({ data: result });
});

// Search users / profiles by username
app.get('/api/profiles', async (req, res) => {
  const q = (req.query.search || '').toString().trim();
  if (q) {
    // case-insensitive substring match
    const docs = await Profile.find({ username: { $regex: q, $options: 'i' } }).sort({ created_at: -1 }).limit(50).lean();
    return res.json({ data: docs });
  }
  // default: return all profiles (limited)
  const all = await Profile.find({}).sort({ created_at: -1 }).limit(100).lean();
  res.json({ data: all });
});

// Moderation actions
app.post('/api/moderation_actions', authMiddleware, async (req, res) => {
  const { message_id, user_id, moderator_id, action_type, reason, expires_at } = req.body;
  const doc = await ModerationAction.create({
    id: uuidv4(),
    message_id,
    user_id,
    moderator_id,
    action_type,
    reason,
    expires_at,
    created_at: new Date().toISOString(),
  });
  res.json({ data: doc });
});

// Annotations (labels) - collect human feedback for model training
app.post('/api/annotations', authMiddleware, async (req, res) => {
  const { message_id, content, labels, source } = req.body;
  const doc = await Annotation.create({
    id: uuidv4(),
    message_id: message_id || null,
    content: content || null,
    labels: labels || {},
    annotator_id: req.user?.id || null,
    source: source || 'user',
    created_at: new Date().toISOString(),
  });
  res.json({ data: doc });
});

app.get('/api/annotations', async (req, res) => {
  const docs = await Annotation.find({}).sort({ created_at: -1 }).limit(1000).lean();
  res.json({ data: docs });
});

// Analyze endpoint - try HF Inference API if configured, otherwise fallback to a lightweight heuristic
app.post('/api/analyze', async (req, res) => {
  const { text } = req.body || {};
  if (!text) return res.status(400).json({ error: 'missing text' });

  // If HF token and model are provided, call the Hugging Face Inference API
  const HF_TOKEN = process.env.HF_API_TOKEN;
  const HF_MODEL = process.env.HF_MODEL || 'facebook/bart-large-mnli';
  try {
    if (HF_TOKEN) {
      const hfRes = await fetch(`https://api-inference.huggingface.co/models/${HF_MODEL}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${HF_TOKEN}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ inputs: text }),
      });
      const hfJson = await hfRes.json();
      // Return raw hf response under 'raw' and map some common fields if present
      const out = { raw: hfJson };
      // best-effort mapping for classification/sentiment outputs
      if (Array.isArray(hfJson)) {
        out.is_abusive = hfJson.some(item => item.label && /toxic|abusive|hate|offensive/i.test(item.label));
      } else if (hfJson.label) {
        out.is_abusive = /toxic|abusive|hate|offensive/i.test(hfJson.label);
      }
      return res.json({ data: out });
    }
  } catch (err) {
    console.warn('HF inference failed:', err.message || err);
  }

  // Fallback heuristic: profanity list and emotion keywords
  const banned = ['fuck','shit','bitch','idiot','stupid','asshole','nigger','fag'];
  const emotionsMap = {
    anger: ['angry','angryly','rage','furious','mad'],
    joy: ['happy','joy','glad','pleased','delighted'],
    sadness: ['sad','unhappy','depressed','sorrow'],
    fear: ['afraid','scared','fear','terrified'],
    disgust: ['disgust','disgusted','gross']
  };
  const textLc = text.toLowerCase();
  let found = [];
  let badCount = 0;
  for (const b of banned) if (textLc.includes(b)) badCount++;
  for (const [emo, kws] of Object.entries(emotionsMap)) {
    for (const k of kws) if (textLc.includes(k)) { found.push(emo); break; }
  }
  const abuse_score = Math.min(1, badCount / 3);
  const is_abusive = abuse_score > 0;
  const analysis = {
    is_abusive,
    abuse_score,
    abuse_type: is_abusive ? 'profanity' : null,
    emotions: found,
  };
  res.json({ data: analysis });
});

// Export dataset (messages + annotations) for offline training
app.get('/api/export-dataset', authMiddleware, async (req, res) => {
  // Only allow admins: simple role check
  const profile = await Profile.findOne({ user_id: req.user.id }).lean();
  if (!profile?.roles?.includes('admin')) return res.status(403).json({ error: 'forbidden' });
  const messages = await Message.find({}).lean();
  const annotations = await Annotation.find({}).lean();
  const payload = { messages, annotations, exported_at: new Date().toISOString() };
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename=dataset.json');
  res.send(JSON.stringify(payload));
});

server.listen(PORT, () => console.log('Backend listening on', PORT));
