require('dotenv').config();
const TelegramBot = require('node-telegram-bot-api');
const { Redis } = require('@upstash/redis');

const token = process.env.TELEGRAM_BOT_TOKEN;
const bot = new TelegramBot(token, { polling: true });

let redis = null;
if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
  redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN,
  });
}

// In-memory state
const waitingQueue = [];
const pairs = new Map(); // userId -> partnerId
const userState = new Map(); // userId -> 'waiting' | 'chatting' | 'idle'

async function isBanned(userId) {
  if (!redis) return false;
  const rec = await redis.get('tgban:' + userId);
  if (!rec) return false;
  if (rec.bannedUntil === null) return true;
  if (rec.bannedUntil && Date.now() < rec.bannedUntil) return true;
  return false;
}

async function trackVisitor(userId) {
  if (!redis) return;
  await redis.sadd('analytics:tg_users', String(userId));
  await redis.incr('analytics:tg_messages_total');
}

function getMainKeyboard() {
  return {
    reply_markup: {
      keyboard: [
        [{ text: '🔍 Find a Stranger' }],
        [{ text: 'ℹ️ About' }, { text: '📊 Stats' }],
      ],
      resize_keyboard: true,
      persistent: true,
    }
  };
}

function getChatKeyboard() {
  return {
    reply_markup: {
      inline_keyboard: [
        [
          { text: '⏭ Next', callback_data: 'next' },
          { text: '🚪 Stop', callback_data: 'stop' },
        ]
      ]
    }
  };
}

function tryMatch(userId) {
  while (waitingQueue.length > 0) {
    const candidateId = waitingQueue[0];
    if (candidateId === userId || userState.get(candidateId) !== 'waiting') {
      waitingQueue.shift();
      continue;
    }
    waitingQueue.shift();
    return candidateId;
  }
  return null;
}

async function findStranger(userId, chatId) {
  if (await isBanned(userId)) {
    bot.sendMessage(chatId, '⛔ You are banned from AnonyChat.');
    return;
  }

  // disconnect from current partner if any
  const currentPartner = pairs.get(userId);
  if (currentPartner) {
    pairs.delete(userId);
    pairs.delete(currentPartner);
    userState.set(currentPartner, 'idle');
    const partnerChatId = currentPartner;
    bot.sendMessage(partnerChatId, '👋 Your stranger left. Use /find to meet someone new.', getMainKeyboard());
  }

  userState.set(userId, 'waiting');
  const partner = tryMatch(userId);

  if (partner) {
    pairs.set(userId, partner);
    pairs.set(partner, userId);
    userState.set(userId, 'chatting');
    userState.set(partner, 'chatting');

    bot.sendMessage(chatId, '✅ *Stranger connected!* Say hi 👋\n\nUse the buttons below to skip or stop.', {
      parse_mode: 'Markdown',
      ...getChatKeyboard()
    });
    bot.sendMessage(partner, '✅ *Stranger connected!* Say hi 👋\n\nUse the buttons below to skip or stop.', {
      parse_mode: 'Markdown',
      ...getChatKeyboard()
    });

    if (redis) await redis.incr('analytics:tg_pairings_total');
  } else {
    waitingQueue.push(userId);
    bot.sendMessage(chatId, '🔍 *Looking for someone...*\n\nYou\'ll be connected automatically when someone is available. Hang tight!', {
      parse_mode: 'Markdown',
      reply_markup: {
        inline_keyboard: [[{ text: '❌ Cancel', callback_data: 'stop' }]]
      }
    });
  }
}

function stopChat(userId, chatId) {
  const partner = pairs.get(userId);
  pairs.delete(userId);
  userState.set(userId, 'idle');

  const queueIdx = waitingQueue.indexOf(userId);
  if (queueIdx !== -1) waitingQueue.splice(queueIdx, 1);

  if (partner) {
    pairs.delete(partner);
    userState.set(partner, 'idle');
    bot.sendMessage(partner, '👋 Your stranger disconnected.\n\nTap *Find a Stranger* to meet someone new!', {
      parse_mode: 'Markdown',
      ...getMainKeyboard()
    });
  }

  bot.sendMessage(chatId, '👋 *Chat ended.* Thanks for using AnonyChat!\n\nTap *Find a Stranger* whenever you\'re ready.', {
    parse_mode: 'Markdown',
    ...getMainKeyboard()
  });
}

// Commands
bot.onText(/\/start/, (msg) => {
  const userId = msg.from.id;
  const chatId = msg.chat.id;
  if (redis) redis.sadd('analytics:tg_users', String(userId));
  bot.sendMessage(chatId,
    '👋 *Welcome to AnonyChat!*\n\n' +
    'Talk to random strangers anonymously — no names, no traces.\n\n' +
    '• Tap *Find a Stranger* to start chatting\n' +
    '• Use ⏭ *Next* to skip to someone new\n' +
    '• Use 🚪 *Stop* to end the chat\n\n' +
    '_Your identity is never revealed._',
    { parse_mode: 'Markdown', ...getMainKeyboard() }
  );
});

bot.onText(/\/find/, (msg) => findStranger(msg.from.id, msg.chat.id));
bot.onText(/\/stop/, (msg) => stopChat(msg.from.id, msg.chat.id));

bot.onText(/\/stats/, async (msg) => {
  const chatId = msg.chat.id;
  if (!redis) {
    bot.sendMessage(chatId, '📊 Stats unavailable.');
    return;
  }
  const totalUsers = await redis.scard('analytics:tg_users');
  const totalMessages = await redis.get('analytics:tg_messages_total') || 0;
  const totalPairings = await redis.get('analytics:tg_pairings_total') || 0;
  const activeChats = pairs.size / 2;
  const waiting = waitingQueue.length;

  bot.sendMessage(chatId,
    `📊 *AnonyChat Bot Stats*\n\n` +
    `👥 Total users: ${totalUsers}\n` +
    `💬 Total messages: ${totalMessages}\n` +
    `🔗 Total pairings: ${totalPairings}\n` +
    `🟢 Active chats: ${activeChats}\n` +
    `⏳ Waiting: ${waiting}`,
    { parse_mode: 'Markdown' }
  );
});

bot.onText(/\/about/, (msg) => {
  bot.sendMessage(msg.chat.id,
    '🔒 *About AnonyChat*\n\n' +
    '*No accounts.* No phone numbers. No history.\n\n' +
    '*Be decent.* Threats get you warned then banned. Zero tolerance for illegal content.\n\n' +
    '🌐 Also available at: https://anonychat-e6hn.onrender.com',
    { parse_mode: 'Markdown', ...getMainKeyboard() }
  );
});

// Keyboard button handlers
bot.on('message', async (msg) => {
  const userId = msg.from.id;
  const chatId = msg.chat.id;
  const text = msg.text || '';

  if (text.startsWith('/')) return; // already handled by onText

  if (text === '🔍 Find a Stranger') {
    findStranger(userId, chatId);
    return;
  }
  if (text === 'ℹ️ About') {
    bot.sendMessage(chatId,
      '🔒 *About AnonyChat*\n\n' +
      '*No accounts.* No phone numbers. No history.\n\n' +
      '*Be decent.* Threats get you warned then banned.\n\n' +
      '🌐 Also at: https://anonychat-e6hn.onrender.com',
      { parse_mode: 'Markdown' }
    );
    return;
  }
  if (text === '📊 Stats') {
    bot.emit('text', { ...msg, text: '/stats' });
    if (!redis) { bot.sendMessage(chatId, '📊 Stats unavailable.'); return; }
    const totalUsers = await redis.scard('analytics:tg_users');
    const totalMessages = await redis.get('analytics:tg_messages_total') || 0;
    const totalPairings = await redis.get('analytics:tg_pairings_total') || 0;
    bot.sendMessage(chatId,
      `📊 *AnonyChat Stats*\n\n👥 Users: ${totalUsers}\n💬 Messages: ${totalMessages}\n🔗 Pairings: ${totalPairings}`,
      { parse_mode: 'Markdown' }
    );
    return;
  }

  // relay message to partner
  const state = userState.get(userId);
  if (state === 'chatting') {
    const partner = pairs.get(userId);
    if (!partner) return;
    if (redis) await redis.incr('analytics:tg_messages_total');

    if (msg.text) {
      bot.sendMessage(partner, `💬 *Stranger:* ${msg.text}`, { parse_mode: 'Markdown' });
    } else if (msg.photo) {
      const photo = msg.photo[msg.photo.length - 1];
      bot.sendPhoto(partner, photo.file_id, { caption: msg.caption ? `💬 Stranger: ${msg.caption}` : '📷 Stranger sent a photo' });
    } else if (msg.sticker) {
      bot.sendSticker(partner, msg.sticker.file_id);
      bot.sendMessage(partner, '🎭 _Stranger sent a sticker_', { parse_mode: 'Markdown' });
    } else if (msg.voice) {
      bot.sendVoice(partner, msg.voice.file_id, { caption: '🎤 Stranger sent a voice message' });
    } else if (msg.video) {
      bot.sendVideo(partner, msg.video.file_id, { caption: '🎥 Stranger sent a video' });
    } else if (msg.gif || msg.animation) {
      bot.sendAnimation(partner, (msg.animation || msg.gif).file_id);
    } else {
      bot.sendMessage(partner, '📎 _Stranger sent an attachment_', { parse_mode: 'Markdown' });
    }
  } else if (state === 'waiting') {
    bot.sendMessage(chatId, '⏳ Still looking for a stranger... please wait.');
  } else {
    bot.sendMessage(chatId, '💡 Tap *Find a Stranger* to start chatting!', {
      parse_mode: 'Markdown',
      ...getMainKeyboard()
    });
  }
});

// Inline button callbacks
bot.on('callback_query', async (query) => {
  const userId = query.from.id;
  const chatId = query.message.chat.id;
  bot.answerCallbackQuery(query.id);

  if (query.data === 'next') {
    await findStranger(userId, chatId);
  } else if (query.data === 'stop') {
    stopChat(userId, chatId);
  }
});

console.log('AnonyChat Telegram bot started');
