const fs = require('fs');
const path = require('path');
const readline = require('readline');
const bcrypt = require('bcryptjs');
const { Redis } = require('@upstash/redis');

const ENV_PATH = path.join(__dirname, '.env.admin-setup');

function loadEnvFile() {
  if (!fs.existsSync(ENV_PATH)) return {};
  const content = fs.readFileSync(ENV_PATH, 'utf8');
  const out = {};
  content.split('\n').forEach(line => {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (m) out[m[1]] = m[2];
  });
  return out;
}

function saveEnvFile(vars) {
  const content = Object.entries(vars).map(([k, v]) => `${k}=${v}`).join('\n');
  fs.writeFileSync(ENV_PATH, content);
  fs.chmodSync(ENV_PATH, 0o600);
}

function ask(question, hidden = false) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    if (!hidden) {
      rl.question(question, (answer) => { rl.close(); resolve(answer.trim()); });
      return;
    }
    const stdin = process.stdin;
    process.stdout.write(question);
    let value = '';
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    const onData = (char) => {
      char = char.toString();
      if (char === '\n' || char === '\r' || char === '\u0004') {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        rl.close();
        resolve(value.trim());
      } else if (char === '\u0003') {
        process.exit();
      } else if (char === '\u007f') {
        value = value.slice(0, -1);
      } else {
        value += char;
      }
    };
    stdin.on('data', onData);
  });
}

async function main() {
  console.log('=== AnonyChat Admin Account Setup ===\n');

  let env = loadEnvFile();

  if (!env.UPSTASH_REDIS_REST_URL) {
    env.UPSTASH_REDIS_REST_URL = await ask('Upstash REST URL: ');
  }
  if (!env.UPSTASH_REDIS_REST_TOKEN) {
    env.UPSTASH_REDIS_REST_TOKEN = await ask('Upstash REST token: ');
  }
  saveEnvFile(env);

  const username = await ask('Choose an admin username: ');
  if (!username) { console.error('Username cannot be empty.'); process.exit(1); }

  let password = '';
  while (password.length < 8) {
    password = await ask('Choose an admin password (min 8 chars, hidden): ', true);
    if (password.length < 8) console.log('Too short, try again.');
  }
  const confirm = await ask('Confirm password: ', true);
  if (confirm !== password) {
    console.error('Passwords did not match. Run the script again.');
    process.exit(1);
  }

  const redis = new Redis({ url: env.UPSTASH_REDIS_REST_URL, token: env.UPSTASH_REDIS_REST_TOKEN });
  const hash = await bcrypt.hash(password, 12);
  await redis.set('admin:user:' + username.toLowerCase(), { username, passwordHash: hash, createdAt: Date.now() });

  console.log('\nDone. Admin account created for username:', username);
  console.log('Go to https://your-app.onrender.com/admin to log in.');
  console.log('(Your Upstash credentials were saved locally to .env.admin-setup so you wont be asked again.)');
}

main().catch(err => { console.error('Failed:', err.message); process.exit(1); });
