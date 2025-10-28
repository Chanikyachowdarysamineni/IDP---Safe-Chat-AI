const mongoose = require('mongoose');

const moderationSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  message_id: String,
  user_id: String,
  moderator_id: String,
  action_type: String,
  reason: String,
  expires_at: String,
  created_at: String,
});

module.exports = mongoose.model('ModerationAction', moderationSchema);
