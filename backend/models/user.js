const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  email: { type: String, unique: true },
  passwordHash: String,
});

module.exports = mongoose.model('User', userSchema);
