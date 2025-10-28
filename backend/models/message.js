const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  // For E2EE: store ciphertext fields only. Plaintext `content` is deprecated and not stored by default.
  // Optional client-side temporary id to reconcile optimistic messages
  client_temp_id: { type: String, default: null },
  content: { type: String, default: null },
  ciphertext: { type: String, default: null },
  nonce: { type: String, default: null },
  sender_pubkey: { type: String, default: null },
  user_id: String,
  recipient_id: String,
  conversation_id: String,
  created_at: String,
  is_abusive: Boolean,
  abuse_score: Number,
  abuse_type: String,
  severity: String,
  emotions: { type: Array, default: [] },
  // read receipts: array of { user_id, read_at }
  read_by: { type: Array, default: [] },
});

module.exports = mongoose.model('Message', messageSchema);
