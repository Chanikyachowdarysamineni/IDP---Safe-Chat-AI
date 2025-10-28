const mongoose = require('mongoose');

const annotationSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  message_id: String,
  content: String,
  labels: { type: Object, default: {} }, // e.g. { toxic: true, emotions: ['anger'] }
  annotator_id: String,
  source: { type: String, default: 'user' }, // 'user' | 'system' | 'admin'
  created_at: String,
});

module.exports = mongoose.model('Annotation', annotationSchema);
