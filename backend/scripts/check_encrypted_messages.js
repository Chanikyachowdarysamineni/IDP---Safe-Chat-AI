const mongoose = require('mongoose');
const Message = require('../models/message');
require('dotenv').config();

const MONGO_URI = process.env.MONGO_URI || process.env.DB_URI || 'mongodb://localhost:27017/emotion-shield';

async function run() {
  try {
    await mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    console.log('Connected to MongoDB at', MONGO_URI);

    const query = { content: '[encrypted]' };
    const count = await Message.countDocuments(query);
    console.log(`Messages with content == '[encrypted]': ${count}`);

    if (count > 0) {
      const samples = await Message.find(query).limit(10).lean();
      console.log('Sample messages (up to 10):');
      for (const m of samples) {
        console.log({ id: m.id, user_id: m.user_id, conversation_id: m.conversation_id, created_at: m.created_at, ciphertext: !!m.ciphertext });
      }
    }

    // Also check messages that have content null but ciphertext present
    const countEncOnly = await Message.countDocuments({ $or: [ { content: null }, { content: { $exists: false } } ], ciphertext: { $ne: null } });
    console.log(`Messages with content null and ciphertext present: ${countEncOnly}`);

    if (countEncOnly > 0) {
      const samples2 = await Message.find({ $or: [ { content: null }, { content: { $exists: false } } ], ciphertext: { $ne: null } }).limit(10).lean();
      console.log('Sample encrypted-only messages (up to 10):');
      for (const m of samples2) {
        console.log({ id: m.id, user_id: m.user_id, conversation_id: m.conversation_id, created_at: m.created_at, ciphertext: !!m.ciphertext });
      }
    }

    await mongoose.disconnect();
    process.exit(0);
  } catch (err) {
    console.error('Error checking messages:', err);
    process.exit(1);
  }
}

run();
