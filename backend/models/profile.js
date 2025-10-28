const mongoose = require('mongoose');

const profileSchema = new mongoose.Schema({
  user_id: { type: String, unique: true },
  username: String,
  // public key for end-to-end encryption (base64 / hex)
  public_key: { type: String, default: null },
  avatar_url: String,
  created_at: String,
  roles: { type: [String], default: ['user'] },
});

module.exports = mongoose.model('Profile', profileSchema);
