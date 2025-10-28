const mongoose = require('mongoose');

const conversationSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  participant_ids: { type: Array, default: [] },
  created_at: String,
  last_message_at: String,
});

module.exports = mongoose.model('Conversation', conversationSchema);
