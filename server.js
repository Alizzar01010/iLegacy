'use strict';

const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const HOST = '0.0.0.0';
const PORT = 80;

const ILEGACY_TURN_URL = process.env.ILEGACY_TURN_URL || '';
const ILEGACY_TURN_SHARED_SECRET = process.env.ILEGACY_TURN_SHARED_SECRET || '';
const ILEGACY_TURN_TTL_SECONDS = 3600;

const SKYGLOW_HTTP_API_URL = process.env.SKYGLOW_HTTP_API_URL || '';
const SKYGLOW_HTTP_API_TOKEN = process.env.SKYGLOW_HTTP_API_TOKEN || '';
const SKYGLOW_HTTP_API_TIMEOUT_MS = 5000;
const SKYGLOW_SERVER_ADDRESS = 'ilegacy.net';
const SKYGLOW_PROTOCOL_VERSION = 2;

const SKYGLOW_TLS_KEY = '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD6sdbXdiLeW/2k\n0YsJSM3G2fh++i+/DknBpDMSm53FPWuSa8Ls0UjfT+p12MrVxxqh/eL/riKbDJE6\nfrdCEw1bPvtnvsZvol+ipdU1+y/vgimV/2W5yQbp3J9tijvQZR43QTV9RUa3s49M\nz2WtLB8iWlpBocywfQXNMkn38GO6Xn9qu5T2jujtdq3KjsWMmgXyPiBoH0Nn8U3X\nHuiNgzHorloDbH+emCcvRb7HhcDW74gbxLGBvHUxtYFU5Q8lI3U1ObjjMfMeH1Ni\n+FqLqIAb836c+aZHnbvS/xHCn0PtuIZN0hj9VQo7+7iYM0W6To8dj50IZ1KmJFTw\nY0cMJww3AgMBAAECggEATgWAHEGHm5WcrKmMcIDIjj0zUe1yY69CNDJytLVa1lKF\nwqWoHkUKPXnlOfUVN5BGUSkvdyyOV5wDLOXYCgfc7ct9ue2NW5v40Kl04F6DLjLf\n12+LjNUsQidoNNLDR9nYnBC+4XRojG6lSB36AnnLXMkq8uc0ya63WgPvMmuN1ifK\nJZpaejDW/Gfsejc3jFETx1NHG16mIq0tlbJe5pAy2O5YXaY6sL5EBFOg1t+m0LJd\nr5ZN9nN3a/0YNP0bNf6nUnTCCBMhytB4+m84e0Suoni+YItjzcLq68RFAhM8Vaeo\nWO9p/zb3bl4Z998tvXO4+pNnAerpe0mYlvTLjVbgYQKBgQD/YdB7CUc1M/NNvD+1\n41un9CyYAzx9V9DNWFANBw6B280OTNFNEjljjT71jNwyUnfsVXX4S4lF+S+NJk22\nzDnHgzFxDL1m3/6QIiXNB1F1z/0b45VVtNKaRLblgpYyVpUZ1fFk1xUv351/f6dI\n2fa9jKGVpxfHZjU5Zo/o3UhXVwKBgQD7TR8WVJW2Ln3CkXwne5mGbv2da/Yj3C+v\ngeCaiTwSCr5zMW5Klyb1Wm0wYYVYHcVwli4fBgxaTAcPHAfFDT/wUND0iAotpSnb\nz41KSwKtwUegAG2awVYzukJDmoHrN2+PII5TLweIthPAsVyeRslDZS8mSIq/xILW\nH5tFNF5GIQKBgQDBlVXBTgEqNR0DGeV5bMR3hcGf4SQjJ0PhxEW5+lVm3kSLyHMH\nZv8VlWXaIFJx2s2I2ic4dZmy7va6mgRiwmAx+iKqPSv9JWIDw76/sgJvuZ91WohC\nlXTm95tkUh6kPbl8Ag6fj+JBjdIHaa5WrNI6ULXTiPufbLx/rFz9+W7ytQKBgBuZ\nxtZPB/pwdMOP8xDrFFudiSFnICukHWCrZR3UANMCdxRz02dB3reH7QIpU9nvuyW4\neOxTX7vzKbtRGtFbuTAN0EVrQ6LrxwMrcps8TdkDp3g9U8xxe6RGysxeBfLtrcUM\nkFU2jx9G0DiTwlZn8+cBEAKmaQbS8IPQCN+69rfBAoGBANK5QMM3Ul3GnbQ0bbNQ\n1F6Fh2cHfX+SEfms+GOWDyDdIqy8PB9o3lFSUVmogRJVmcVv7y6tsT49XliaylSc\ntlLT8TA5UIZSG/96Omh1KGMYVtQk7nCHh3oA+c3iSCi/VAoXU1Bv+Mm0LSg9z9Tk\nIyUSvfybApCuCJbmLiOffD22\n-----END PRIVATE KEY-----\n';
const SKYGLOW_TLS_CERT = '-----BEGIN CERTIFICATE-----\nMIIDDTCCAfWgAwIBAgIUKvdS0oe+roBu3TB8qDe6wSkySGswDQYJKoZIhvcNAQEL\nBQAwFjEUMBIGA1UEAwwLaWxlZ2FjeS5uZXQwHhcNMjYxMDIyMjIzNTE4WhcNNDYx\nMDE3MjIzNTE4WjAWMRQwEgYDVQQDDAtpbGVnYWN5Lm5ldDCCASIwDQYJKoZIhvcN\nAQEBBQADggEPADCCAQoCggEBAPqx1td2It5b/aTRiwlIzcbZ+H76L78OScGkMxKb\nncU9a5JrwuzRSN9P6nXYytXHGqH94v+uIpsMkTp+t0ITDVs++2e+xm+iX6Kl1TX7\nL++CKZX/ZbnJBuncn22KO9BlHjdBNX1FRrezj0zPZa0sHyJaWkGhzLB9Bc0ySffw\nY7pef2q7lPaO6O12rcqOxYyaBfI+IGgfQ2fxTdce6I2DMeiuWgNsf56YJy9FvseF\nwNbviBvEsYG8dTG1gVTlDyUjdTU5uOMx8x4fU2L4WouogBvzfpz5pkedu9L/EcKf\nQ+24hk3SGP1VCjv7uJgzRbpOjx2PnQhnUqYkVPBjRwwnDDcCAwEAAaNTMFEwHQYD\nVR0OBBYEFBhlkxfzQW0eReEOzfkFAbI2zz4vMB8GA1UdIwQYMBaAFBhlkxfzQW0e\nReEOzfkFAbI2zz4vMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\nAGydUuP9ZigZbSzAUO817KNcZjF9lVQvSSqtMbO0IXurfzmEAt4f4pVIGc3ZLSn+\nrLOlZXhNY5pFytDi67WXo5olKHzn4sCv3KjJ1QhuzN5rDkWzYN9iOUKdObhqL8Aa\nNuycvbyl8cdrbXx2WmUj+L3gINbjHmSGLMfgK95mzNALuBUMwjuPs0h2x3bPWjB7\n6kDqR6k18OjHL7Bdz3m7X34+tL+RA2DDVp9waw13Y4MyqsaNFc3cQ59RipIXkeJR\ncmLGfE4RJMHW8aXxfMrd74nMJVpIk3cIqNJx61uU5LNbzQRRge6DW50HeRygeZnK\nl31nX12z4p8zXvn3jK4dx3w=\n-----END CERTIFICATE-----\n';
const SKYGLOW_MAX_PAYLOAD = 4096;
const SKYGLOW_E2EE_SALT_SUFFIX = 'Hello from the Skyglow Notifications developers!';

const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const DEB_DIR = path.join(DATA_DIR, 'debs');
const NEWS_DIR = path.join(DATA_DIR, 'news');
const DRIVE_DIR = path.join(DATA_DIR, 'drive');
const LOG_DIR = path.join(__dirname, 'logs');

const DB_FILE = path.join(DATA_DIR, 'db.json');
const LOG_FILE = path.join(LOG_DIR, 'server.log');

const MAX_BODY = 7 * 1024 * 1024;
const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const MAX_MESSAGE_LEN = 4000;
const MAX_CAPTION_LEN = 1000;
const MAX_DEB_BYTES = 200 * 1024 * 1024;

const DEB_TAGS = ['Major Update', 'Bug Fix', 'Untested', 'Beta', 'Security Fix'];

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(DEB_DIR, { recursive: true });
fs.mkdirSync(NEWS_DIR, { recursive: true });
fs.mkdirSync(DRIVE_DIR, { recursive: true });
fs.mkdirSync(LOG_DIR, { recursive: true });

const logViewers = new Set();

function log(level, message) {
  const line = `${new Date().toISOString()} [${level}] ${message}`;

  console.log(line);

  fs.appendFile(LOG_FILE, line + '\n', () => {});

  for (const res of logViewers) {
    if (!res.destroyed) res.write(`data: ${line}\n\n`);
  }
}

let db = {
  users: {},
  usernames: {},
  sessions: {},
  messages: [],
  posts: [],
  downloadCategories: [],
  debs: [],
  news: [],
  newsMedia: {},
  socialMedia: {},
  downloadLog: [],
  uploadLog: [],
  albums: [],
  driveFiles: {},
  driveQuotas: {},
  skyglowTokens: {},
  skyglowIdentities: {},
  skyglowFilters: {},
  skyglowQueue: {},
  skyglowNextSeq: {}
};

if (fs.existsSync(DB_FILE)) {
  try {
    db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    for (const k of ['users', 'usernames', 'sessions', 'newsMedia', 'socialMedia', 'driveFiles', 'driveQuotas',
      'skyglowTokens', 'skyglowIdentities', 'skyglowFilters', 'skyglowQueue', 'skyglowNextSeq']) {
      if (!db[k] || typeof db[k] !== 'object') db[k] = {};
    }
    for (const k of ['messages', 'posts', 'downloadCategories', 'debs', 'news', 'downloadLog', 'uploadLog', 'albums']) {
      if (!Array.isArray(db[k])) db[k] = [];
    }

    log(
      'INFO',
      `Loaded ${Object.keys(db.users).length} users, ` +
      `${db.messages.length} messages, ${db.posts.length} posts`
    );
  } catch (err) {
    log('ERROR', 'Could not read db.json: ' + err.message);
    process.exit(1);
  }
}

let saveTimer = null;

function saveDb() {
  if (saveTimer) clearTimeout(saveTimer);

  saveTimer = setTimeout(() => {
    saveTimer = null;
    const tempFile = DB_FILE + '.tmp';
    fs.writeFile(tempFile, JSON.stringify(db), (err) => {
      if (err) {
        log('ERROR', 'Database save failed: ' + err.message);
        return;
      }

      fs.rename(tempFile, DB_FILE, (renameErr) => {
        if (renameErr) {
          log('ERROR', 'Database rename failed: ' + renameErr.message);
        }
      });
    });
  }, 200);
}

function saveDbImmediately() {
  if (saveTimer) {
    clearTimeout(saveTimer);
    saveTimer = null;
  }

  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(db));
  } catch (err) {
    log('ERROR', 'Immediate database save failed: ' + err.message);
  }
}

function send(res, status, obj) {
  if (res.headersSent) {
    res.end();
    return true;
  }

  const body = JSON.stringify(obj);

  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store'
  });

  res.end(body);
  return true;
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    let finished = false;
    req.on('data', (chunk) => {
      if (finished) return;
      size += chunk.length;
      if (size > MAX_BODY) {
        finished = true;
        reject(new Error('Request too large. Maximum request size is 7 MB.'));
        req.resume();
        return;
      }

      chunks.push(chunk);
    });

    req.on('end', () => {
      if (finished) return;
      if (!chunks.length) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', (err) => {
      if (!finished) reject(err);
    });
  });
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function newUserId() {
  let id;

  do {
    id = 'IL-' + crypto.randomInt(10000000, 100000000);
  } while (db.users[id]);

  return id;
}

function newToken() {
  return crypto.randomBytes(32).toString('hex');
}

function getToken(req, url) {
  const header = req.headers.authorization || '';

  if (header.startsWith('Bearer ')) {
    return header.slice(7);
  }

  return url.searchParams.get('token') || '';
}

function authUser(req, url) {
  const token = getToken(req, url);

  if (!token) return null;

  const session = db.sessions[token];

  if (!session) return null;

  return db.users[session.userId] || null;
}

const ADMIN_IDS = new Set(['IL-90059101', 'IL-54786703']);

function isAdmin(user) {
  return !!user && ADMIN_IDS.has(user.userId);
}

function publicUser(user) {
  return {
    userId: user.userId,
    username: user.username,
    displayName: user.displayName,
    createdAt: user.createdAt,
    isAdmin: isAdmin(user)
  };
}

function validUsername(username) {
  return typeof username === 'string' &&
    /^[a-zA-Z0-9_]{3,20}$/.test(username);
}

const attempts = new Map();

function tooManyAttempts(ip) {
  const now = Date.now();

  const list = (attempts.get(ip) || [])
    .filter((time) => now - time < 60000);

  list.push(now);
  attempts.set(ip, list);

  return list.length > 10;
}

const liveClients = new Map();

const activeCalls = new Map();
const CALL_RING_TIMEOUT_MS = 45000;
const CALL_SIGNAL_MAX_BYTES = 128 * 1024;

function callForUser(userId) {
  for (const call of activeCalls.values()) {
    if (call.from === userId || call.to === userId) return call;
  }
  return null;
}

function publicCall(call) {
  return {
    callId: call.id,
    from: call.from,
    to: call.to,
    createdAt: call.createdAt
  };
}

function finishCall(callId, endedBy, reason) {
  const call = activeCalls.get(callId);
  if (!call) return false;
  clearTimeout(call.timeout);
  activeCalls.delete(callId);
  const event = { callId: call.id, endedBy: endedBy || null, reason: reason || 'ended' };
  pushToUser(call.from, 'call_ended', event);
  pushToUser(call.to, 'call_ended', event);
  log('CALL', `Call ${call.id} ${reason || 'ended'} by ${endedBy || 'server'}`);
  return true;
}

const skyglowConnections = new Map();
const skyglowRouteConnections = new Map();

function sgnFrame(type, payload = Buffer.alloc(0)) {
  if (!Buffer.isBuffer(payload)) payload = Buffer.from(payload);
  if (payload.length > SKYGLOW_MAX_PAYLOAD) throw new Error('Skyglow payload too large');
  const h = Buffer.alloc(8);
  h[0] = 0x53; h[1] = 0x02; h[2] = type; h[3] = 0;
  h.writeUInt32BE(payload.length, 4);
  return Buffer.concat([h, payload]);
}
function sgnSend(session, type, payload = Buffer.alloc(0)) {
  if (!session || session.socket.destroyed) return;
  try { session.socket.write(sgnFrame(type, payload)); } catch (e) { log('SKYGLOW', 'Frame send failed: ' + e.message); }
}
function sgnInt64(value) { const b = Buffer.alloc(8); b.writeBigInt64BE(BigInt(value)); return b; }
function sgnRegisterFail(session, reason, code = 1) {
  const msg = Buffer.from(String(reason).slice(0, 250), 'utf8');
  const p = Buffer.alloc(3 + msg.length); p[0] = code; p.writeUInt16BE(msg.length, 1); msg.copy(p, 3);
  sgnSend(session, 0x19, p);
}
function sgnVerify(publicKey, signedBytes, signature) {
  try {
    return crypto.verify('sha256', signedBytes, {
      key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32
    }, signature);
  } catch (_) { return false; }
}
function sgnRemoveSession(session) {
  if (session.address && skyglowConnections.get(session.address) === session) skyglowConnections.delete(session.address);
  for (const key of session.routeKeys || []) {
    const set = skyglowRouteConnections.get(key);
    if (set) { set.delete(session); if (!set.size) skyglowRouteConnections.delete(key); }
  }
}
function sgnApplyFilters(session, payload) {
  if (payload.length < 3) return;
  const flags = payload[0], count = payload.readUInt16BE(1);
  let off = 3; const parsed = [];
  for (let i = 0; i < count; i++) {
    if (off + 35 > payload.length) return;
    const tag = payload[off]; const routeKey = payload.subarray(off + 1, off + 33).toString('hex');
    const bidLen = payload.readUInt16BE(off + 33); off += 35;
    if (off + bidLen > payload.length) return;
    const bundleId = payload.subarray(off, off + bidLen).toString('utf8'); off += bidLen;
    parsed.push({ tag, routeKey, bundleId });
  }
  if (off !== payload.length) return;

  session.pendingFilters = (flags & 1) ? (session.pendingFilters || []).concat(parsed) : (session.pendingFilters || []).concat(parsed);
  if (flags & 1) return;
  sgnRemoveSession(session);
  session.routeKeys = [];
  if (session.address) skyglowConnections.set(session.address, session);
  for (const item of session.pendingFilters) {
    if (item.tag !== 1 || !/^[a-f0-9]{64}$/.test(item.routeKey)) continue;
    if (!skyglowRouteConnections.has(item.routeKey)) skyglowRouteConnections.set(item.routeKey, new Set());
    skyglowRouteConnections.get(item.routeKey).add(session);
    session.routeKeys.push(item.routeKey);
    db.skyglowFilters[item.routeKey] = { bundleId: item.bundleId, enabled: true, updatedAt: Date.now() };
  }
  session.pendingFilters = [];
  saveDb();
}
function sgnNotifyFrame(routeHex, payloadObject, seq) {
  const tokenHex = Object.values(db.skyglowTokens || {}).map(x => x && x.deviceToken).find(t => {
    if (!/^[a-f0-9]{64}$/i.test(t || '')) return false;
    const b = Buffer.from(t, 'hex');
    return crypto.createHash('sha256').update(b.subarray(16, 32)).digest('hex') === routeHex;
  });
  if (!tokenHex) return null;
  const token = Buffer.from(tokenHex, 'hex');
  const secretK = token.subarray(16, 32);
  const salt = Buffer.concat([Buffer.from(SKYGLOW_SERVER_ADDRESS), Buffer.from(SKYGLOW_E2EE_SALT_SUFFIX)]);
  const e2ee = Buffer.from(crypto.hkdfSync('sha256', secretK, salt, Buffer.alloc(0), 32));
  const iv = crypto.randomBytes(12);
  const plaintext = Buffer.from(JSON.stringify(payloadObject), 'utf8');
  const cipher = crypto.createCipheriv('aes-256-gcm', e2ee, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  const msgId = crypto.randomBytes(16);
  const header = Buffer.alloc(70);
  Buffer.from(routeHex, 'hex').copy(header, 0);
  msgId.copy(header, 32);
  header.writeBigInt64BE(BigInt(seq), 48);
  header.writeBigInt64BE(0n, 56);
  header[64] = 1;
  header[65] = 1;
  header.writeUInt32BE(encrypted.length, 66);
  return { frame: sgnFrame(0x13, Buffer.concat([header, encrypted, iv])), msgId: msgId.toString('hex'), seq };
}
function sgnDeliver(routeHex, payloadObject) {
  const next = (Number(db.skyglowNextSeq[routeHex]) || 0) + 1;
  db.skyglowNextSeq[routeHex] = next;
  const item = sgnNotifyFrame(routeHex, payloadObject, next);
  if (!item) return false;
  if (!Array.isArray(db.skyglowQueue[routeHex])) db.skyglowQueue[routeHex] = [];
  db.skyglowQueue[routeHex].push({ msgId: item.msgId, seq: next, frame: item.frame.toString('base64'), createdAt: Date.now() });
  const sessions = skyglowRouteConnections.get(routeHex);
  if (sessions) for (const session of sessions) {
    if (!session.socket.destroyed) session.socket.write(item.frame);
  }
  saveDb();
  return true;
}
function sgnReplayQueue(session, lastSeq = 0) {
  for (const routeHex of session.routeKeys || []) {
    for (const item of (db.skyglowQueue[routeHex] || [])) {
      if (Number(item.seq) > Number(lastSeq)) {
        try { session.socket.write(Buffer.from(item.frame, 'base64')); } catch (_) {}
      }
    }
  }
  sgnSend(session, 0x17);
}
function sgnHandleFrame(session, type, payload) {
  if (type === 0x00) return;
  if (type === 0x28) {
    if (payload.length < 14) return sgnRegisterFail(session, 'Malformed registration');
    const pubLen = payload.readUInt16BE(0);
    if (pubLen < 100 || pubLen > 2048 || payload.length !== 2 + pubLen + 12) return sgnRegisterFail(session, 'Invalid public key');
    const der = payload.subarray(2, 2 + pubLen);
    let publicKey;
    try { publicKey = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' }); }
    catch (_) { return sgnRegisterFail(session, 'Invalid public key'); }
    const timestamp = payload.readBigInt64BE(2 + pubLen);
    const version = payload.readUInt32BE(10 + pubLen);
    if (version !== SKYGLOW_PROTOCOL_VERSION || Math.abs(Number(timestamp) - Math.floor(Date.now()/1000)) > 172800) return sgnRegisterFail(session, 'Version or timestamp rejected', 5);
    session.pendingRegistration = { publicKey, der, timestamp };
    session.challenge = crypto.randomBytes(32); session.phase = 'register-challenge';
    sgnSend(session, 0x11, session.challenge);
    return;
  }
  if (type === 0x29 && session.phase === 'register-challenge') {
    if (payload.length < 10) return sgnRegisterFail(session, 'Malformed registration response');
    const timestamp = payload.readBigInt64BE(0), sigLen = payload.readUInt16BE(8);
    if (payload.length !== 10 + sigLen || Math.abs(Number(timestamp) - Math.floor(Date.now()/1000)) > 172800) return sgnRegisterFail(session, 'Invalid registration timestamp');
    const signed = Buffer.concat([session.challenge, sgnInt64(timestamp)]);
    if (!sgnVerify(session.pendingRegistration.publicKey, signed, payload.subarray(10))) return sgnRegisterFail(session, 'Registration signature rejected');
    const address = crypto.randomBytes(16).toString('hex') + '@' + SKYGLOW_SERVER_ADDRESS;
    db.skyglowIdentities[address] = { publicKeyDer: session.pendingRegistration.der.toString('base64'), createdAt: Date.now() };
    saveDbImmediately();
    session.address = address; session.publicKey = session.pendingRegistration.publicKey; session.phase = 'authenticated';
    const addr = Buffer.from(address, 'utf8'); const result = Buffer.alloc(6 + addr.length);
    result.writeUInt32BE(SKYGLOW_PROTOCOL_VERSION, 0); result.writeUInt16BE(addr.length, 4); addr.copy(result, 6);
    sgnSend(session, 0x18, result);
    session.authenticated = true; skyglowConnections.set(address, session);
    return;
  }
  if (type === 0x20) {
    if (payload.length < 14) return sgnRegisterFail(session, 'Malformed login');
    const n = payload.readUInt16BE(0);
    if (payload.length !== 2 + n + 12) return sgnRegisterFail(session, 'Malformed login');
    const address = payload.subarray(2, 2 + n).toString('utf8');
    const timestamp = payload.readBigInt64BE(2 + n), version = payload.readUInt32BE(10 + n);
    const identity = db.skyglowIdentities[address];
    if (!identity || version !== SKYGLOW_PROTOCOL_VERSION || Math.abs(Number(timestamp)-Math.floor(Date.now()/1000)) > 172800) return sgnRegisterFail(session, 'Unknown identity or timestamp', 1);
    try { session.publicKey = crypto.createPublicKey({ key: Buffer.from(identity.publicKeyDer, 'base64'), format: 'der', type: 'spki' }); }
    catch (_) { return sgnRegisterFail(session, 'Stored identity is invalid', 3); }
    session.address = address; session.loginTimestamp = timestamp; session.challenge = crypto.randomBytes(32); session.phase = 'login-challenge';
    sgnSend(session, 0x11, session.challenge); return;
  }
  if (type === 0x21 && session.phase === 'login-challenge') {
    if (payload.length < 10) return sgnRegisterFail(session, 'Malformed login response');
    const timestamp = payload.readBigInt64BE(0), sigLen = payload.readUInt16BE(8);
    if (payload.length !== 10 + sigLen) return sgnRegisterFail(session, 'Malformed login signature');
    const signed = Buffer.concat([session.challenge, Buffer.from(session.address, 'utf8'), sgnInt64(timestamp)]);
    if (!sgnVerify(session.publicKey, signed, payload.subarray(10))) return sgnRegisterFail(session, 'Login signature rejected', 1);
    session.phase = 'authenticated'; session.authenticated = true; skyglowConnections.set(session.address, session);
    sgnSend(session, 0x12);
    sgnSend(session, 0x1B, sgnInt64(Math.floor(Date.now()/1000)));
    return;
  }
  if (!session.authenticated) return sgnSend(session, 0x14, Buffer.from([1]));
  if (type === 0x2B) return sgnApplyFilters(session, payload);
  if (type === 0x27) return sgnSend(session, 0x16, payload.subarray(0, 8));
  if (type === 0x2A) return;
  if (type === 0x22) return sgnReplayQueue(session, payload.length >= 8 ? Number(payload.readBigInt64BE(0)) : 0);
  if (type === 0x23 && payload.length >= 17) {
    const msgId = payload.subarray(0, 16).toString('hex');
    for (const routeHex of Object.keys(db.skyglowQueue || {})) {
      db.skyglowQueue[routeHex] = (db.skyglowQueue[routeHex] || []).filter(q => q.msgId !== msgId);
    }
    saveDb(); return;
  }
  if (type === 0x24) { session.socket.end(); return; }
}
function sgnHandleSocket(socket) {
  const session = { socket, phase: 'hello', authenticated: false, routeKeys: [], buffer: Buffer.alloc(0), pendingFilters: [] };
  socket.setNoDelay(true);
  sgnSend(session, 0x10, Buffer.from([0,0,0,2]));
  socket.on('data', chunk => {
    session.buffer = Buffer.concat([session.buffer, chunk]);
    while (session.buffer.length >= 8) {
      const b = session.buffer;
      if (b[0] !== 0x53 || b[1] !== 0x02 || b[3] !== 0) { socket.destroy(); return; }
      const len = b.readUInt32BE(4);
      if (len > SKYGLOW_MAX_PAYLOAD) { socket.destroy(); return; }
      if (b.length < 8 + len) break;
      const type = b[2], payload = b.subarray(8, 8 + len);
      session.buffer = b.subarray(8 + len);
      try { sgnHandleFrame(session, type, payload); } catch (e) { log('SKYGLOW', 'Protocol handler error: ' + e.message); socket.destroy(); return; }
    }
  });
  socket.on('close', () => sgnRemoveSession(session));
  socket.on('error', e => { if (e && e.code !== 'ECONNRESET') log('SKYGLOW', 'TCP connection: ' + e.message); });
}
function sgnQueueFromToken(deviceToken, payloadObject) {
  if (!/^[a-f0-9]{64}$/i.test(deviceToken || '')) return false;
  const token = Buffer.from(deviceToken, 'hex');
  const serverAddress = token.subarray(0, 16).toString('utf8').replace(/\0+$/, '');
  if (serverAddress !== SKYGLOW_SERVER_ADDRESS) return false;
  const routeHex = crypto.createHash('sha256').update(token.subarray(16, 32)).digest('hex');
  return sgnDeliver(routeHex, payloadObject);
}

function sendSkyglowPush(userId, eventName, data) {
  if (!db.skyglowTokens || !db.skyglowTokens[userId]) return;
  if (!['message', 'notification', 'call_invite'].includes(eventName)) return;

  const registration = db.skyglowTokens[userId];
  if (!registration || !/^[a-f0-9]{64}$/i.test(registration.deviceToken || '')) return;

  let title = 'iLegacy';
  let body = 'You have a new notification';
  if (eventName === 'message') {
    title = 'New message';
    body = (data && (data.text || data.caption)) || 'You received a message';
    if (data && data.from) {
      const sender = db.users[data.from];
      if (sender && sender.username) title = 'Message from ' + sender.username;
    }
  } else if (eventName === 'notification') {
    const n = data || {};
    const sender = n.from || {};
    title = sender.username ? sender.username : 'iLegacy';
    const labels = {
      friend_request: 'sent you a friend request', friend_accepted: 'accepted your friend request',
      follow: 'started following you', like: 'liked your post', comment: 'commented on your post'
    };
    body = labels[n.type] || n.text || 'You have a new notification';
  } else if (eventName === 'call_invite') {
    title = 'Incoming iLegacy call';
    body = 'Someone is calling you';
  }

  const payload = {
    aps: { alert: { title: String(title).slice(0, 100), body: String(body).slice(0, 240) }, sound: 'default' },
    app: 'com.ilegacy.app', event: eventName,
    notification_id: data && (data.id || data.callId) ? String(data.id || data.callId) : ''
  };
  const nativeQueued = sgnQueueFromToken(registration.deviceToken, payload);
  if (nativeQueued) log('SKYGLOW', `Queued native Skyglow notification for ${userId}`);
  if (!SKYGLOW_HTTP_API_URL) return;
  let target;
  try { target = new URL(SKYGLOW_HTTP_API_URL); } catch (_) {
    log('SKYGLOW', 'Invalid SKYGLOW_HTTP_API_URL; push skipped');
    return;
  }
  if (target.protocol !== 'https:' && target.protocol !== 'http:') {
    log('SKYGLOW', 'SKYGLOW_HTTP_API_URL must use HTTP or HTTPS');
    return;
  }
  const transport = target.protocol === 'https:' ? https : http;

  const bodyJson = JSON.stringify({
    device_token: registration.deviceToken, deviceToken: registration.deviceToken,
    token: registration.deviceToken, bundle_id: registration.bundleId || 'com.ilegacy.app',
    bundleId: registration.bundleId || 'com.ilegacy.app', payload, notification: payload
  });
  const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bodyJson) };
  if (SKYGLOW_HTTP_API_TOKEN) headers.Authorization = 'Bearer ' + SKYGLOW_HTTP_API_TOKEN;
  const request = transport.request(target, { method: 'POST', headers, timeout: SKYGLOW_HTTP_API_TIMEOUT_MS }, (response) => {
    response.resume();
    if (response.statusCode < 200 || response.statusCode >= 300) {
      log('SKYGLOW', `Push API returned HTTP ${response.statusCode}`);
    }
  });
  request.on('timeout', () => request.destroy(new Error('Skyglow HTTP request timed out')));
  request.on('error', (err) => log('SKYGLOW', 'Push request failed: ' + err.message));
  request.end(bodyJson);
}

function pushToUser(userId, eventName, data) {
  sendSkyglowPush(userId, eventName, data);
  const clients = liveClients.get(userId);

  if (!clients) return;

  for (const res of clients) {
    if (!res.destroyed) {
      res.write(
        `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`
      );
    }
  }
}

setInterval(() => {
  for (const clients of liveClients.values()) {
    for (const res of clients) {
      if (!res.destroyed) res.write(': ping\n\n');
    }
  }

  for (const res of logViewers) {
    if (!res.destroyed) res.write(': ping\n\n');
  }
}, 25000);

function isConnected(userId) {
  const clients = liveClients.get(userId);
  return !!(clients && clients.size);
}

function isInvisible(userId) {
  const profile = db.profiles && db.profiles[userId];
  return !!(profile && profile.invisible);
}

function presenceOf(userId) {
  return isConnected(userId) && !isInvisible(userId);
}

function broadcastPresence(userId) {
  const data = { userId, online: presenceOf(userId) };

  for (const id of liveClients.keys()) {
    pushToUser(id, 'presence', data);
  }
}

function schedulePresenceCheck(userId) {
  setTimeout(() => {
    if (!isConnected(userId)) {
      const call = callForUser(userId);
      if (call) finishCall(call.id, userId, 'disconnected');
      broadcastPresence(userId);
    }
  }, 3000);
}

const IMAGE_TYPES = {
  'image/jpeg': {
    extension: '.jpg',
    matches: (b) =>
      b.length >= 3 &&
      b[0] === 0xff &&
      b[1] === 0xd8 &&
      b[2] === 0xff
  },

  'image/png': {
    extension: '.png',
    matches: (b) =>
      b.length >= 8 &&
      b.subarray(0, 8).equals(
        Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])
      )
  },

  'image/gif': {
    extension: '.gif',
    matches: (b) =>
      b.length >= 6 &&
      ['GIF87a', 'GIF89a'].includes(b.subarray(0, 6).toString('ascii'))
  },

  'image/webp': {
    extension: '.webp',
    matches: (b) =>
      b.length >= 12 &&
      b.subarray(0, 4).toString('ascii') === 'RIFF' &&
      b.subarray(8, 12).toString('ascii') === 'WEBP'
  }
};

function imageUrl(filename, token) {
  return '/uploads/' + encodeURIComponent(filename) +
    '?token=' + encodeURIComponent(token);
}

function createSocial(ctx) {
  const {
    db, log, saveDb, saveDbImmediately, send, readJson, pushToUser,
    publicUser, validUsername, isAdmin, IMAGE_TYPES, imageUrl, UPLOAD_DIR, MAX_IMAGE_BYTES
  } = ctx;

  const DEFAULT_BG = '#f0f2f5';
  const MAX_NAME = 40;
  const MAX_BIO = 300;
  const MAX_COMMENT = 500;
  const MAX_NOTIFICATIONS = 5000;

  function newProfile() {
    return {
      bio: '',
      bgColor: DEFAULT_BG,
      avatar: null,
      invisible: false,
      darkMode: false,
      createdAt: Date.now()
    };
  }

  function migrate() {
    if (!db.profiles) db.profiles = {};
    if (!db.comments) db.comments = [];
    if (!db.notifications) db.notifications = [];
    if (!db.follows) db.follows = {};
    if (!db.friends || typeof db.friends !== 'object') db.friends = {};
    if (!Array.isArray(db.friendRequests)) db.friendRequests = [];
    let created = 0;
    for (const id of Object.keys(db.users)) {
      if (!db.profiles[id]) {
        db.profiles[id] = newProfile();
        created++;
      }
    }

    let fixedPosts = 0;
    for (const post of db.posts) {
      if (!Array.isArray(post.likes)) {
        post.likes = [];
        fixedPosts++;
      }
    }

    if (created || fixedPosts) saveDb();
    log(
      'PROFILE',
      `Profile pages ready: ${Object.keys(db.profiles).length} total ` +
      `(${created} created this run, ${fixedPosts} posts upgraded for likes)`
    );
  }

  function getProfile(userId) {
    if (!db.users[userId]) return null;
    if (!db.profiles[userId]) {
      db.profiles[userId] = newProfile();
      saveDb();
    }
    if (typeof db.profiles[userId].darkMode !== 'boolean') {
      db.profiles[userId].darkMode = false;
    }
    return db.profiles[userId];
  }

  function card(user, token) {
    const out = publicUser(user);
    const profile = db.profiles[user.userId];
    out.avatarUrl = (profile && profile.avatar && token)
      ? imageUrl(profile.avatar, token)
      : null;
    return out;
  }

  function commentCounts() {
    const counts = {};
    for (const c of db.comments) counts[c.postId] = (counts[c.postId] || 0) + 1;
    return counts;
  }

  function postView(post, token, meId, counts) {
    const author = db.users[post.userId];
    if (!author) return null;
    const likes = Array.isArray(post.likes) ? post.likes : [];
    return {
      id: post.id,
      user: card(author, token),
      caption: post.caption,
      imageUrl: post.mediaId ? null : imageUrl(post.filename, token),
      mediaId: post.mediaId || null,
      mediaKind: post.mediaKind || (post.filename && /\.gif$/i.test(post.filename) ? 'image' : null),
      mediaMimeType: post.mediaMimeType || post.mimeType || null,
      mediaUrl: post.mediaId ? ('/social/media/' + post.mediaId) : null,
      ts: post.ts,
      likeCount: likes.length,
      liked: likes.includes(meId),
      commentCount: counts[post.id] || 0
    };
  }

  function commentView(c, token) {
    const author = db.users[c.userId];
    if (!author) return null;
    return {
      id: c.id,
      postId: c.postId,
      user: card(author, token),
      text: c.text,
      ts: c.ts
    };
  }

  function followersOf(userId) {
    let n = 0;
    for (const list of Object.values(db.follows)) {
      if (list.includes(userId)) n++;
    }
    return n;
  }

  function followingOf(userId) {
    return (db.follows[userId] || []).length;
  }

  function friendsOf(userId) {
    return db.friends[userId] || [];
  }

  function findRequest(from, to) {
    return db.friendRequests.find((r) => r.from === from && r.to === to);
  }

  function friendStatus(meId, otherId) {
    if (meId === otherId) return 'self';
    if (friendsOf(meId).includes(otherId)) return 'friends';
    if (findRequest(meId, otherId)) return 'outgoing';
    if (findRequest(otherId, meId)) return 'incoming';
    return 'none';
  }

  function makeFriends(a, b) {
    if (!db.friends[a]) db.friends[a] = [];
    if (!db.friends[b]) db.friends[b] = [];
    if (!db.friends[a].includes(b)) db.friends[a].push(b);
    if (!db.friends[b].includes(a)) db.friends[b].push(a);
  }

  function unfriend(a, b) {
    db.friends[a] = friendsOf(a).filter((x) => x !== b);
    db.friends[b] = friendsOf(b).filter((x) => x !== a);
  }

  function dropFriendRequests(a, b) {
    db.friendRequests = db.friendRequests.filter((r) =>
      !((r.from === a && r.to === b) || (r.from === b && r.to === a))
    );
    removeNotifications((n) =>
      n.type === 'friend_request' &&
      ((n.from === a && n.userId === b) || (n.from === b && n.userId === a))
    );
  }

  function profileView(user, me, token) {
    const profile = getProfile(user.userId);
    const out = card(user, token);
    out.bio = profile.bio || '';
    out.bgColor = profile.bgColor || DEFAULT_BG;
    out.followersCount = followersOf(user.userId);
    out.followingCount = followingOf(user.userId);
    out.isFollowing = (db.follows[me.userId] || []).includes(user.userId);
    out.isMe = user.userId === me.userId;
    out.postCount = db.posts.filter((p) => p.userId === user.userId).length;
    out.online = presenceOf(user.userId);
    if (out.isMe) out.invisible = !!profile.invisible;
    if (out.isMe) out.darkMode = !!profile.darkMode;
    out.friendStatus = friendStatus(me.userId, user.userId);
    out.friendsCount = friendsOf(user.userId).length;
    return out;
  }

  function notify(type, toUserId, fromUserId, extra) {
    if (toUserId === fromUserId) return null;
    if (!db.users[toUserId]) return null;
    const n = Object.assign({
      id: crypto.randomUUID(),
      userId: toUserId,
      type,
      from: fromUserId,
      ts: Date.now(),
      read: false
    }, extra || {});

    db.notifications.push(n);
    if (db.notifications.length > MAX_NOTIFICATIONS) {
      db.notifications = db.notifications.slice(-MAX_NOTIFICATIONS);
    }

    const sender = db.users[fromUserId];
    pushToUser(toUserId, 'notification', {
      id: n.id,
      type: n.type,
      from: sender ? publicUser(sender) : null,
      postId: n.postId || null,
      text: n.text || null,
      reason: n.reason || null,
      ts: n.ts
    });

    return n;
  }

  function removeNotifications(test) {
    db.notifications = db.notifications.filter((n) => !test(n));
  }

  function notificationView(n, token) {
    const sender = db.users[n.from];
    if (!sender) return null;
    let postImageUrl = null;
    if (n.postId) {
      const post = db.posts.find((p) => p.id === n.postId);
      if (post) postImageUrl = imageUrl(post.filename, token);
    }

    return {
      id: n.id,
      type: n.type,
      from: card(sender, token),
      postId: n.postId || null,
      postImageUrl,
      text: n.text || null,
      reason: n.reason || null,
      requestPending: n.type === 'friend_request' ? !!findRequest(n.from, n.userId) : false,
      ts: n.ts,
      read: !!n.read
    };
  }

  function decode(s) {
    try { return decodeURIComponent(s); } catch { return null; }
  }

  function readImage(mimeType, imageData) {
    if (!Object.prototype.hasOwnProperty.call(IMAGE_TYPES, mimeType)) {
      return { error: 'Choose a JPEG, PNG, GIF, or WebP image' };
    }

    if (typeof imageData !== 'string' || !imageData.length) {
      return { error: 'Image data is missing' };
    }

    if (
      imageData.length > Math.ceil(MAX_IMAGE_BYTES * 4 / 3) + 8 ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(imageData) ||
      imageData.length % 4 !== 0
    ) {
      return { error: 'Invalid image data or image too large' };
    }

    const buffer = Buffer.from(imageData, 'base64');
    if (!buffer.length || buffer.length > MAX_IMAGE_BYTES) {
      return { error: 'Image must be between 1 byte and 5 MB' };
    }

    const type = IMAGE_TYPES[mimeType];
    if (!type.matches(buffer)) {
      return { error: 'File contents do not match the selected image type' };
    }

    return { buffer, type };
  }

  function sendUploadedFile(res, filename) {
    const filePath = path.join(UPLOAD_DIR, filename);
    if (!fs.existsSync(filePath)) {
      send(res, 404, { error: 'Image file is missing' });
      return;
    }

    const mime = {
      '.jpg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.webp': 'image/webp'
    }[path.extname(filename)];
    res.writeHead(200, {
      'Content-Type': mime,
      'Content-Length': fs.statSync(filePath).size,
      'Cache-Control': 'private, max-age=3600',
      'X-Content-Type-Options': 'nosniff'
    });

    fs.createReadStream(filePath).pipe(res);
  }

  async function handle(req, res, url, me, token) {
    const p = url.pathname;
    const method = req.method;
    let m;
    if (method === 'POST' && (m = p.match(/^\/admin\/posts\/([^/]+)\/delete$/))) {
      if (!isAdmin(me)) return send(res, 403, { error: 'Admin access required' });

      let postId;
      try { postId = decode(m[1]); } catch (_) { postId = null; }
      if (!postId) return send(res, 400, { error: 'Invalid post ID' });

      let body;
      try { body = await readJson(req); } catch (_) {
        return send(res, 400, { error: 'Invalid request body' });
      }
      const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
      if (!reason || reason.length > 500) {
        return send(res, 400, { error: 'A deletion reason of 1Ã¢â‚¬â€œ500 characters is required' });
      }

      const post = db.posts.find((item) => item.id === postId);
      if (!post) return send(res, 404, { error: 'No such post' });

      const relatedComments = db.comments.filter((item) => item.postId === postId);
      const commentIds = new Set(relatedComments.map((item) => item.id));
      db.comments = db.comments.filter((item) => item.postId !== postId);
      removeNotifications((item) =>
        item.postId === postId || (item.commentId && commentIds.has(item.commentId))
      );
      db.posts = db.posts.filter((item) => item.id !== postId);
      const filename = post.filename;
      if (post.mediaId && db.socialMedia && db.socialMedia[post.mediaId]) {
        const rec = db.socialMedia[post.mediaId];
        try { fs.unlinkSync(path.join(UPLOAD_DIR, rec.filename)); } catch (_) {}
        delete db.socialMedia[post.mediaId];
      }
      if (typeof filename === 'string' && path.basename(filename) === filename &&
          /^[a-f0-9-]+\.(jpg|png|gif|webp)$/i.test(filename)) {
        try {
          fs.unlinkSync(path.join(UPLOAD_DIR, filename));
        } catch (err) {
          if (err.code !== 'ENOENT') log('WARN', 'Could not remove deleted post image: ' + err.message);
        }
      }

      if (!Array.isArray(db.moderationLogs)) db.moderationLogs = [];
      const ts = Date.now();
      db.moderationLogs.push({
        id: crypto.randomUUID(),
        action: 'delete_post',
        moderatorId: me.userId,
        postId: postId,
        authorId: post.userId,
        reason: reason,
        ts: ts
      });
      if (db.moderationLogs.length > 10000) {
        db.moderationLogs = db.moderationLogs.slice(-10000);
      }

      notify('post_deleted', post.userId, me.userId, {
        postId: null,
        reason: reason,
        text: 'Your post was deleted. Reason: ' + reason
      });

      saveDbImmediately();
      log('MODERATION', me.userId + ' deleted post ' + postId + ' by ' + post.userId + '; reason: ' + reason);
      return send(res, 200, { ok: true, postId: postId });
    }

    if (method === 'GET' && p === '/posts') {
      const counts = commentCounts();
      const posts = db.posts
        .slice()
        .sort((a, b) => b.ts - a.ts)
        .slice(0, 200)
        .map((post) => postView(post, token, me.userId, counts))
        .filter(Boolean);
      return send(res, 200, { posts });
    }

    if (method === 'POST' && (m = p.match(/^\/posts\/([^/]+)\/(like|unlike)$/))) {
      const postId = decode(m[1]);
      const post = db.posts.find((x) => x.id === postId);
      if (!post) return send(res, 404, { error: 'No such post' });

      if (!Array.isArray(post.likes)) post.likes = [];
      if (m[2] === 'like') {
        if (!post.likes.includes(me.userId)) {
          post.likes.push(me.userId);
          notify('like', post.userId, me.userId, { postId: post.id });
          log('LIKE', `${me.userId} liked post ${post.id}`);
        }
      } else {
        const i = post.likes.indexOf(me.userId);
        if (i !== -1) {
          post.likes.splice(i, 1);
          removeNotifications((n) =>
            n.type === 'like' && n.from === me.userId && n.postId === post.id
          );
          log('LIKE', `${me.userId} unliked post ${post.id}`);
        }
      }

      saveDb();
      return send(res, 200, {
        liked: post.likes.includes(me.userId),
        likeCount: post.likes.length
      });
    }

    if (method === 'GET' && (m = p.match(/^\/posts\/([^/]+)\/comments$/))) {
      const postId = decode(m[1]);
      if (!db.posts.some((x) => x.id === postId)) return send(res, 404, { error: 'No such post' });

      const comments = db.comments
        .filter((c) => c.postId === postId)
        .sort((a, b) => a.ts - b.ts)
        .slice(-300)
        .map((c) => commentView(c, token))
        .filter(Boolean);
      return send(res, 200, { comments });
    }

    if (method === 'POST' && (m = p.match(/^\/posts\/([^/]+)\/comments$/))) {
      const postId = decode(m[1]);
      const post = db.posts.find((x) => x.id === postId);
      if (!post) return send(res, 404, { error: 'No such post' });

      const { text } = await readJson(req);
      if (
        typeof text !== 'string' ||
        !text.trim() ||
        text.length > MAX_COMMENT
      ) {
        return send(res, 400, {
          error: `Comment must be 1-${MAX_COMMENT} characters`
        });
      }

      const comment = {
        id: crypto.randomUUID(),
        postId: post.id,
        userId: me.userId,
        text: text.trim(),
        ts: Date.now()
      };

      db.comments.push(comment);
      notify('comment', post.userId, me.userId, {
        postId: post.id,
        commentId: comment.id,
        text: comment.text.slice(0, 140)
      });

      saveDb();
      log('COMMENT', `${me.userId} commented on post ${post.id}`);
      return send(res, 201, {
        comment: commentView(comment, token),
        commentCount: db.comments.filter((c) => c.postId === post.id).length
      });
    }

    if (method === 'POST' && (m = p.match(/^\/comments\/([^/]+)\/delete$/))) {
      const commentId = decode(m[1]);
      const comment = db.comments.find((c) => c.id === commentId);
      if (!comment) return send(res, 404, { error: 'No such comment' });

      const post = db.posts.find((x) => x.id === comment.postId);
      const isOwner = post && post.userId === me.userId;
      if (comment.userId !== me.userId && !isOwner) {
        return send(res, 403, { error: 'You can only delete your own comments' });
      }

      db.comments = db.comments.filter((c) => c.id !== commentId);
      removeNotifications((n) => n.commentId === commentId);
      saveDb();
      log('COMMENT', `${me.userId} deleted comment ${commentId}`);
      return send(res, 200, {
        ok: true,
        commentCount: db.comments.filter((c) => c.postId === comment.postId).length
      });
    }

    if (method === 'GET' && (m = p.match(/^\/profiles\/([^/]+)$/))) {
      const id = decode(m[1]);
      const target = id ? db.users[id] : null;
      if (!target) return send(res, 404, { error: 'No such user' });

      const counts = commentCounts();
      const posts = db.posts
        .filter((post) => post.userId === target.userId)
        .sort((a, b) => b.ts - a.ts)
        .slice(0, 200)
        .map((post) => postView(post, token, me.userId, counts))
        .filter(Boolean);
      return send(res, 200, { profile: profileView(target, me, token), posts });
    }

    if (method === 'POST' && p === '/profile') {
      const body = await readJson(req);
      const profile = getProfile(me.userId);
      let newName = null;
      let newUsername = null;
      let newBio = null;
      let newBg = null;
      let newInvisible = null;
      let newDarkMode = null;
      if (body.displayName !== undefined) {
        newName = typeof body.displayName === 'string'
          ? body.displayName.trim()
          : '';
        if (!newName || newName.length > MAX_NAME) {
          return send(res, 400, { error: `Name must be 1-${MAX_NAME} characters` });
        }
      }

      if (body.username !== undefined) {
        if (!validUsername(body.username)) {
          return send(res, 400, {
            error: 'Username must be 3-20 characters: letters, numbers, underscore'
          });
        }

        const owner = db.usernames[body.username.toLowerCase()];
        if (owner && owner !== me.userId) return send(res, 409, { error: 'Username already taken' });

        newUsername = body.username;
      }

      if (body.bio !== undefined) {
        if (typeof body.bio !== 'string' || body.bio.length > MAX_BIO) {
          return send(res, 400, { error: `Bio must be ${MAX_BIO} characters or fewer` });
        }

        newBio = body.bio.trim();
      }

      if (body.bgColor !== undefined) {
        if (
          typeof body.bgColor !== 'string' ||
          !/^#[0-9a-fA-F]{6}$/.test(body.bgColor)
        ) {
          return send(res, 400, { error: 'Background color must look like #RRGGBB' });
        }

        newBg = body.bgColor.toLowerCase();
      }

      if (body.invisible !== undefined) {
        if (typeof body.invisible !== 'boolean') return send(res, 400, { error: 'Invisible must be true or false' });

        newInvisible = body.invisible;
      }

      if (body.darkMode !== undefined) {
        if (typeof body.darkMode !== 'boolean') return send(res, 400, { error: 'Dark mode must be true or false' });
        newDarkMode = body.darkMode;
      }

      if (newName !== null) me.displayName = newName;
      if (newUsername !== null) {
        delete db.usernames[me.username.toLowerCase()];
        db.usernames[newUsername.toLowerCase()] = me.userId;
        me.username = newUsername;
      }

      if (newBio !== null) profile.bio = newBio;
      if (newBg !== null) profile.bgColor = newBg;
      if (newDarkMode !== null) profile.darkMode = newDarkMode;
      const invisibleChanged = newInvisible !== null && !!profile.invisible !== newInvisible;
      if (newInvisible !== null) profile.invisible = newInvisible;

      saveDb();
      log('PROFILE', `${me.userId} updated their profile`);
      if (invisibleChanged) {
        log('PRESENCE', `${me.userId} is now ${newInvisible ? 'invisible' : 'visible'}`);
        broadcastPresence(me.userId);
      }

      return send(res, 200, { profile: profileView(me, me, token) });
    }

    if (method === 'POST' && p === '/profile/avatar') {
      const body = await readJson(req);
      const profile = getProfile(me.userId);
      const oldFile = profile.avatar;
      if (body.remove === true) {
        profile.avatar = null;
      } else {
        const img = readImage(body.mimeType, body.imageData);
        if (img.error) return send(res, 400, { error: img.error });

        const filename = crypto.randomUUID() + img.type.extension;
        try {
          fs.writeFileSync(path.join(UPLOAD_DIR, filename), img.buffer, { flag: 'wx' });
        } catch (err) {
          log('ERROR', 'Avatar save failed: ' + err.message);
          return send(res, 500, { error: 'Could not save image on the server computer' });
        }

        profile.avatar = filename;
      }

      saveDb();
      if (oldFile && oldFile !== profile.avatar) {
        fs.unlink(path.join(UPLOAD_DIR, oldFile), () => {});
      }

      log('PROFILE', `${me.userId} changed their profile picture`);
      return send(res, 200, { profile: profileView(me, me, token) });
    }

    if (method === 'POST' && (m = p.match(/^\/users\/([^/]+)\/(follow|unfollow)$/))) {
      const id = decode(m[1]);
      const target = id ? db.users[id] : null;
      if (!target) return send(res, 404, { error: 'No such user' });

      if (target.userId === me.userId) return send(res, 400, { error: "You can't follow yourself" });

      if (!db.follows[me.userId]) db.follows[me.userId] = [];
      const list = db.follows[me.userId];
      if (m[2] === 'follow') {
        if (!list.includes(target.userId)) {
          list.push(target.userId);
          notify('follow', target.userId, me.userId, {});
          log('FOLLOW', `${me.userId} followed ${target.userId}`);
        }
      } else {
        const i = list.indexOf(target.userId);
        if (i !== -1) {
          list.splice(i, 1);
          removeNotifications((n) =>
            n.type === 'follow' && n.from === me.userId && n.userId === target.userId
          );
          log('FOLLOW', `${me.userId} unfollowed ${target.userId}`);
        }
      }

      saveDb();
      return send(res, 200, {
        following: list.includes(target.userId),
        followersCount: followersOf(target.userId)
      });
    }

    if (method === 'POST' &&
        (m = p.match(/^\/friends\/(request|cancel|accept|decline|remove)\/([^/]+)$/))) {
      let action = m[1];
      const id = decode(m[2]);
      const target = id ? db.users[id] : null;
      if (!target) return send(res, 404, { error: 'No such user' });

      if (target.userId === me.userId) return send(res, 400, { error: "You can't friend yourself" });

      const status = friendStatus(me.userId, target.userId);
      if (action === 'request' && status === 'incoming') action = 'accept';
      if (action === 'request') {
        if (status === 'friends') return send(res, 400, { error: 'You are already friends' });
        if (status === 'outgoing') return send(res, 400, { error: 'Friend request already sent' });

        db.friendRequests.push({
          id: crypto.randomUUID(),
          from: me.userId,
          to: target.userId,
          ts: Date.now()
        });
        notify('friend_request', target.userId, me.userId, {});
        log('FRIEND', `${me.userId} sent a friend request to ${target.userId}`);
      } else if (action === 'cancel') {
        if (status !== 'outgoing') return send(res, 400, { error: 'There is no pending request to cancel' });
        dropFriendRequests(me.userId, target.userId);
        log('FRIEND', `${me.userId} cancelled their request to ${target.userId}`);
      } else if (action === 'accept') {
        if (status !== 'incoming') return send(res, 400, { error: 'That person has not sent you a friend request' });
        dropFriendRequests(me.userId, target.userId);
        makeFriends(me.userId, target.userId);
        notify('friend_accepted', target.userId, me.userId, {});
        log('FRIEND', `${me.userId} accepted ${target.userId}'s friend request`);
      } else if (action === 'decline') {
        if (status !== 'incoming') return send(res, 400, { error: 'That person has not sent you a friend request' });
        dropFriendRequests(me.userId, target.userId);
        log('FRIEND', `${me.userId} declined ${target.userId}'s friend request`);
      } else {
        if (status !== 'friends') return send(res, 400, { error: 'You are not friends with this person' });
        unfriend(me.userId, target.userId);
        log('FRIEND', `${me.userId} unfriended ${target.userId}`);
      }

      saveDb();
      pushToUser(target.userId, 'friend_update', { userId: me.userId });

      return send(res, 200, {
        friendStatus: friendStatus(me.userId, target.userId),
        friendsCount: friendsOf(target.userId).length
      });
    }

    if (method === 'GET' && p === '/notifications') {
      const mine = db.notifications.filter((n) => n.userId === me.userId);
      const notifications = mine
        .slice()
        .sort((a, b) => b.ts - a.ts)
        .slice(0, 100)
        .map((n) => notificationView(n, token))
        .filter(Boolean);
      return send(res, 200, {
        notifications,
        unread: mine.filter((n) => !n.read).length
      });
    }

    if (method === 'GET' && p === '/notifications/count') {
      return send(res, 200, {
        unread: db.notifications.filter((n) => n.userId === me.userId && !n.read).length
      });
    }

    if (method === 'POST' && p === '/notifications/read') {
      const body = await readJson(req);
      const ids = Array.isArray(body.ids) ? new Set(body.ids) : null;
      for (const n of db.notifications) {
        if (n.userId === me.userId && (!ids || ids.has(n.id))) n.read = true;
      }

      saveDb();
      return send(res, 200, {
        ok: true,
        unread: db.notifications.filter((n) => n.userId === me.userId && !n.read).length
      });
    }

    if (method === 'GET' && p.startsWith('/uploads/')) {
      const filename = decode(p.slice('/uploads/'.length));
      if (
        !filename ||
        path.basename(filename) !== filename ||
        !/^[a-f0-9-]+\.(jpg|png|gif|webp)$/.test(filename)
      ) {
        return false;
      }

      const isAvatar = Object.values(db.profiles).some((pr) => pr.avatar === filename);
      if (!isAvatar) return false;
      sendUploadedFile(res, filename);
      return true;
    }

    return false;
  }

  return { migrate, handle, postView, commentCounts, readImage };
}

const social = createSocial({
  db, log, saveDb, saveDbImmediately, send, readJson, pushToUser,
  publicUser, validUsername, isAdmin, IMAGE_TYPES, imageUrl, UPLOAD_DIR, MAX_IMAGE_BYTES
});

social.migrate();

const MAX_CATEGORY_NAME = 40;
const MAX_CATEGORIES = 100;
const MAX_ACTIVITY_LOG = 50000;

function logUpload(deb) {
  db.uploadLog.push({
    id: crypto.randomUUID(),
    debId: deb.id,
    userId: deb.uploadedBy,
    name: deb.name,
    bundleId: deb.bundleId,
    version: deb.version,
    size: deb.size,
    ts: deb.uploadedAt
  });

  if (db.uploadLog.length > MAX_ACTIVITY_LOG) {
    db.uploadLog = db.uploadLog.slice(-MAX_ACTIVITY_LOG);
  }
}

function logDownload(userId, deb) {
  db.downloadLog.push({
    id: crypto.randomUUID(),
    debId: deb.id,
    userId,
    name: deb.name,
    bundleId: deb.bundleId,
    version: deb.version,
    ts: Date.now()
  });

  if (db.downloadLog.length > MAX_ACTIVITY_LOG) {
    db.downloadLog = db.downloadLog.slice(-MAX_ACTIVITY_LOG);
  }
}

(function backfillUploadLog() {
  const known = new Set(db.uploadLog.map((u) => u.debId));
  let added = 0;

  for (const deb of db.debs) {
    if (!known.has(deb.id)) {
      logUpload(deb);
      added++;
    }
  }

  if (added) {
    saveDb();
    log('DOWNLOADS', `Backfilled ${added} existing upload(s) into the upload history`);
  }
})();

function userBrief(userId) {
  const u = db.users[userId];

  return u
    ? { userId: u.userId, username: u.username, displayName: u.displayName }
    : { userId, username: '', displayName: 'Deleted user' };
}

function cleanText(value, max) {
  if (typeof value !== 'string') return '';
  return value.replace(/[\x00-\x1f\x7f]/g, ' ').trim().slice(0, max);
}

function debView(deb) {
  const uploader = db.users[deb.uploadedBy];

  return {
    id: deb.id,
    categoryId: deb.categoryId,
    name: deb.name,
    author: deb.author,
    bundleId: deb.bundleId,
    version: deb.version,
    description: deb.description || '',
    minIOS: deb.minIOS || '',
    maxIOS: deb.maxIOS || '',
    size: deb.size,
    sha256: deb.sha256,
    fileName: deb.fileName,
    uploadedAt: deb.uploadedAt,
    uploadedBy: uploader ? uploader.displayName : 'Unknown',
    downloads: deb.downloads || 0,
    tag: deb.tag || '',
    editedAt: deb.editedAt || null
  };
}

function downloadsOverview() {
  return db.downloadCategories.map((category) => ({
    id: category.id,
    name: category.name,
    createdAt: category.createdAt,
    debs: db.debs
      .filter((deb) => deb.categoryId === category.id)
      .sort((a, b) => b.uploadedAt - a.uploadedAt)
      .map(debView)
  }));
}

function removeDebFile(deb) {
  if (typeof deb.filename !== 'string' || !/^[a-f0-9-]+\.(deb|exe)$/.test(deb.filename)) {
    return;
  }

  try {
    fs.unlinkSync(path.join(DEB_DIR, deb.filename));
  } catch (err) {
    if (err.code !== 'ENOENT') {
      log('WARN', 'Could not remove .deb file: ' + err.message);
    }
  }
}

function receiveDeb(req, tmpPath, ext) {
  const isExe = ext === '.exe';
  const headLen = isExe ? 2 : 8;
  const kindLabel = isExe ? '.exe' : '.deb';
  const validHead = (buf) => isExe
    ? buf.toString('latin1') === 'MZ'
    : buf.toString('latin1') === '!<arch>\n';

  return new Promise((resolve, reject) => {
    const out = fs.createWriteStream(tmpPath, { flags: 'wx' });
    const hash = crypto.createHash('sha256');
    let size = 0;
    let head = Buffer.alloc(0);
    let failed = false;
    function fail(err) {
      if (failed) return;
      failed = true;
      out.destroy();
      fs.unlink(tmpPath, () => {});
      req.resume();
      reject(err);
    }

    req.on('data', (chunk) => {
      if (failed) return;
      size += chunk.length;
      if (size > MAX_DEB_BYTES) {
        fail(new Error('File too large. Maximum size is 200 MB.'));
        return;
      }

      if (head.length < headLen) {
        head = Buffer.concat([head, chunk.subarray(0, headLen - head.length)]);
        if (head.length === headLen && !validHead(head)) {
          fail(new Error('That file is not a valid ' + kindLabel + ' file'));
          return;
        }
      }

      hash.update(chunk);
      if (!out.write(chunk)) {
        req.pause();
        out.once('drain', () => req.resume());
      }
    });

    req.on('end', () => {
      if (failed) return;
      if (head.length < headLen) {
        fail(new Error('That file is not a valid ' + kindLabel + ' file'));
        return;
      }

      out.end(() => resolve({ size, sha256: hash.digest('hex') }));
    });

    req.on('error', fail);
    out.on('error', fail);
  });
}

const NEWS_MAX_ATTACH = 10;

const NEWS_LIMITS = {
  image: 5 * 1024 * 1024,
  audio: 5 * 1024 * 1024,
  video: 7.5 * 1024 * 1024 * 1024,
  zip: 750 * 1024 * 1024
};

function formatLimit(bytes) {
  return bytes >= 1073741824
    ? (bytes / 1073741824) + ' GB'
    : (bytes / 1048576) + ' MB';
}

function mediaDisposition(rec) {
  if (rec.kind !== 'zip') return 'inline';

  let safe = String(rec.name || 'download.zip').replace(/[^A-Za-z0-9._ -]/g, '_');
  if (!/\.zip$/i.test(safe)) safe += '.zip';

  return 'attachment; filename="' + safe + '"';
}

const NEWS_FONTS = [
  'Arial', 'Helvetica', 'Georgia', 'Times New Roman', 'Courier New',
  'Verdana', 'Trebuchet MS', 'Comic Sans MS', 'Impact',
  'Palatino Linotype', 'Tahoma', 'Lucida Console'
];
const NEWS_GENERIC_FONTS = ['serif', 'sans-serif', 'monospace', 'cursive', 'fantasy'];
const NEWS_TAGS = new Set([
  'p', 'div', 'br', 'hr', 'b', 'strong', 'i', 'em', 'u', 's', 'strike',
  'sub', 'sup', 'span', 'font', 'h1', 'h2', 'h3', 'ul', 'ol', 'li',
  'blockquote', 'a'
]);
const NEWS_VOID_TAGS = new Set(['br', 'hr']);
const NEWS_COLOR_RE =
  /^(#[0-9a-f]{3,8}|rgba?\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*(,\s*[0-9.]+\s*)?\)|[a-z]{3,30})$/i;

function decodeAttr(value) {
  return String(value)
    .replace(/&quot;|&#34;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

function parseHtmlAttrs(text) {
  const attrs = {};
  const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
  let m;

  while ((m = re.exec(text))) {
    const name = m[1].toLowerCase();
    const raw = m[2] !== undefined ? m[2] : (m[3] !== undefined ? m[3] : (m[4] || ''));
    if (!(name in attrs)) attrs[name] = decodeAttr(raw);
  }

  return attrs;
}

function cleanFontList(value) {
  const out = [];

  for (const piece of String(value).split(',')) {
    const name = piece.trim().replace(/^["']|["']$/g, '').trim();
    const known = NEWS_FONTS.find((f) => f.toLowerCase() === name.toLowerCase());
    if (known) out.push("'" + known + "'");
    else if (NEWS_GENERIC_FONTS.includes(name.toLowerCase())) out.push(name.toLowerCase());
  }

  return out.join(',');
}

function cleanNewsStyle(style) {
  const out = [];

  for (const part of String(style).split(';')) {
    const i = part.indexOf(':');
    if (i < 0) continue;
    const prop = part.slice(0, i).trim().toLowerCase();
    const val = part.slice(i + 1).trim();
    if (!val || val.length > 120) continue;
    if (prop === 'color' || prop === 'background-color') {
      if (NEWS_COLOR_RE.test(val)) out.push(prop + ':' + val);
    } else if (prop === 'font-family') {
      const fonts = cleanFontList(val);
      if (fonts) out.push('font-family:' + fonts);
    } else if (prop === 'font-size') {
      const m = val.match(/^(\d{1,3}(?:\.\d+)?)(px|pt)$/);
      if (m && Number(m[1]) >= 8 && Number(m[1]) <= 96) out.push('font-size:' + m[1] + m[2]);
    } else if (prop === 'font-weight') {
      if (/^(bold|normal|[1-9]00)$/.test(val)) out.push('font-weight:' + val);
    } else if (prop === 'font-style') {
      if (/^(italic|normal)$/.test(val)) out.push('font-style:' + val);
    } else if (prop === 'text-decoration' || prop === 'text-decoration-line') {
      if (/^(underline|line-through|none)( (underline|line-through))*$/.test(val)) {
        out.push(prop + ':' + val);
      }
    } else if (prop === 'text-align') {
      if (/^(left|right|center|justify)$/.test(val)) out.push('text-align:' + val);
    }
  }

  return out.join(';');
}

function sanitizeNewsHtml(input) {
  const html = String(input || '')
    .slice(0, 80000)
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(script|style|iframe|object|embed|template|noscript|svg|math)\b[\s\S]*?<\/\1\s*>/gi, '');

  const tagRe = /<(\/?)([a-zA-Z][a-zA-Z0-9]*)((?:"[^"]*"|'[^']*'|[^'">])*)>/g;
  const escText = (s) => s.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const stack = [];
  let out = '';
  let last = 0;
  let m;

  while ((m = tagRe.exec(html))) {
    out += escText(html.slice(last, m.index));
    last = tagRe.lastIndex;
    const closing = m[1] === '/';
    const tag = m[2].toLowerCase();
    if (!NEWS_TAGS.has(tag)) continue;
    if (closing) {
      const idx = stack.lastIndexOf(tag);
      if (idx < 0) continue;
      while (stack.length > idx) out += '</' + stack.pop() + '>';
      continue;
    }

    const attrs = parseHtmlAttrs(m[3]);
    let attrOut = '';
    if (attrs.style) {
      const style = cleanNewsStyle(attrs.style);
      if (style) attrOut += ' style="' + style + '"';
    }

    if (tag === 'font') {
      if (attrs.color && NEWS_COLOR_RE.test(attrs.color)) attrOut += ' color="' + attrs.color + '"';
      if (attrs.size && /^[1-7]$/.test(attrs.size)) attrOut += ' size="' + attrs.size + '"';
      if (attrs.face) {
        const face = cleanFontList(attrs.face);
        if (face) attrOut += ' face="' + face + '"';
      }
    }

    if (tag === 'a') {
      const href = (attrs.href || '').trim();
      if (/^https?:\/\//i.test(href) && href.length < 500 && !/["'<>\s]/.test(href)) {
        attrOut += ' href="' + href + '" target="_blank" rel="noopener noreferrer"';
      }
    }

    out += '<' + tag + attrOut + '>';
    if (!NEWS_VOID_TAGS.has(tag)) stack.push(tag);
  }

  out += escText(html.slice(last));
  while (stack.length) out += '</' + stack.pop() + '>';

  return out;
}

function sniffNewsMedia(b) {
  if (b.length < 12) return null;

  for (const [mimeType, type] of Object.entries(IMAGE_TYPES)) {
    if (type.matches(b)) return { kind: 'image', mimeType, ext: type.extension };
  }

  const head3 = b.subarray(0, 3).toString('latin1');
  if (head3 === 'ID3' || (b[0] === 0xff && (b[1] & 0xe0) === 0xe0)) {
    return { kind: 'audio', mimeType: 'audio/mpeg', ext: '.mp3' };
  }

  if (b.subarray(0, 4).toString('latin1') === 'RIFF' &&
      b.subarray(8, 12).toString('latin1') === 'WAVE') {
    return { kind: 'audio', mimeType: 'audio/wav', ext: '.wav' };
  }

  if (b.subarray(0, 4).toString('latin1') === 'OggS') {
    return { kind: 'audio', mimeType: 'audio/ogg', ext: '.ogg' };
  }

  if (b.subarray(4, 8).toString('latin1') === 'ftyp') {
    const brand = b.subarray(8, 12).toString('latin1');
    if (brand === 'M4A ' || brand === 'M4B ') {
      return { kind: 'audio', mimeType: 'audio/mp4', ext: '.m4a' };
    }
    return { kind: 'video', mimeType: 'video/mp4', ext: '.mp4' };
  }

  if (b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) {
    return { kind: 'zip', mimeType: 'application/zip', ext: '.zip' };
  }

  return null;
}

function receiveNewsMedia(req, tmpPath, opts) {
  const allowZip = !!(opts && opts.allowZip);

  return new Promise((resolve, reject) => {
    const out = fs.createWriteStream(tmpPath, { flags: 'wx' });
    let size = 0;
    let head = Buffer.alloc(0);
    let type = null;
    let failed = false;
    function fail(err) {
      if (failed) return;
      failed = true;
      out.destroy();
      fs.unlink(tmpPath, () => {});
      req.resume();
      reject(err);
    }

    req.on('data', (chunk) => {
      if (failed) return;
      size += chunk.length;
      if (size > NEWS_LIMITS.video) {
        fail(new Error('File too large (max ' + formatLimit(NEWS_LIMITS.video) + ')'));
        return;
      }

      if (!type) {
        head = Buffer.concat([head, chunk.subarray(0, 12 - head.length)]);
        if (head.length >= 12) {
          type = sniffNewsMedia(head);
          if (!type) {
            fail(new Error('Unsupported file. Use JPEG, PNG, GIF, WebP, MP3, WAV, OGG, M4A, MP4' +
              (allowZip ? ' or ZIP.' : '.')));
            return;
          }

          if (type.kind === 'zip' && !allowZip) {
            fail(new Error('ZIP files can only be sent in DMs and announcements'));
            return;
          }
        }
      }

      if (type && size > NEWS_LIMITS[type.kind]) {
        fail(new Error('That ' + type.kind + ' file is too large (max ' +
          formatLimit(NEWS_LIMITS[type.kind]) + ')'));
        return;
      }

      if (!out.write(chunk)) {
        req.pause();
        out.once('drain', () => req.resume());
      }
    });

    req.on('end', () => {
      if (failed) return;
      if (!type) {
        fail(new Error('Unsupported or empty file'));
        return;
      }

      out.end(() => resolve({ size, kind: type.kind, mimeType: type.mimeType, ext: type.ext }));
    });

    req.on('aborted', () => fail(new Error('Upload cancelled')));
    req.on('error', fail);
    out.on('error', fail);
  });
}

function removeNewsMedia(id) {
  const rec = db.newsMedia[id];
  if (!rec) return;

  if (/^[a-f0-9-]+\.[a-z0-9]{2,4}$/.test(rec.filename)) {
    try {
      fs.unlinkSync(path.join(NEWS_DIR, rec.filename));
    } catch (err) {
      if (err.code !== 'ENOENT') log('WARN', 'Could not remove news file: ' + err.message);
    }
  }

  delete db.newsMedia[id];
}

function cleanupOrphanNewsMedia() {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  let removed = 0;

  for (const id of Object.keys(db.newsMedia)) {
    const rec = db.newsMedia[id];
    if (!rec.newsId && rec.ts < cutoff) {
      removeNewsMedia(id);
      removed++;
    }
  }

  if (removed) {
    saveDb();
    log('NEWS', 'Removed ' + removed + ' unused uploaded file(s)');
  }
}

cleanupOrphanNewsMedia();
setInterval(cleanupOrphanNewsMedia, 60 * 60 * 1000);

function cleanupOrphanSocialMedia() {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  let removed = 0;

  for (const id of Object.keys(db.socialMedia || {})) {
    const rec = db.socialMedia[id];
    if (!rec.messageId && !rec.postId && rec.ts < cutoff) {
      if (/^[a-f0-9-]+\.[a-z0-9]{2,4}$/.test(rec.filename)) {
        try { fs.unlinkSync(path.join(UPLOAD_DIR, rec.filename)); } catch (_) {}
      }
      delete db.socialMedia[id];
      removed++;
    }
  }

  if (removed) {
    saveDb();
    log('MEDIA', 'Removed ' + removed + ' unused uploaded file(s)');
  }
}

cleanupOrphanSocialMedia();
setInterval(cleanupOrphanSocialMedia, 60 * 60 * 1000);

function newsMediaView(id) {
  const rec = db.newsMedia[id];
  if (!rec) return null;

  return {
    id: rec.id,
    kind: rec.kind,
    mimeType: rec.mimeType,
    name: rec.name,
    size: rec.size,
    url: '/news/media/' + rec.id
  };
}

function newsView(n) {
  const author = db.users[n.authorId];

  return {
    id: n.id,
    title: n.title,
    html: n.html,
    media: n.media.map(newsMediaView).filter(Boolean),
    author: author
      ? { userId: author.userId, username: author.username, displayName: author.displayName }
      : { userId: '', username: '', displayName: 'Unknown' },
    ts: n.ts,
    editedAt: n.editedAt || null
  };
}

function parseNewsBody(body, existingId) {
  const title = cleanText(body && body.title, 100);
  if (!title) return { error: 'Enter a title' };

  const html = sanitizeNewsHtml(body.html);
  if (html.length > 40000) return { error: 'The announcement text is too long' };

  const ids = Array.isArray(body.mediaIds) ? body.mediaIds : [];
  if (ids.length > NEWS_MAX_ATTACH) {
    return { error: 'You can attach up to ' + NEWS_MAX_ATTACH + ' files' };
  }

  const mediaIds = [];

  for (const id of ids) {
    if (typeof id !== 'string' || !/^[a-f0-9-]{36}$/.test(id) ||
        !Object.prototype.hasOwnProperty.call(db.newsMedia, id)) {
      return { error: 'An attached file no longer exists. Remove it and upload it again.' };
    }

    const rec = db.newsMedia[id];
    if (rec.newsId && rec.newsId !== existingId) {
      return { error: 'An attached file already belongs to another announcement' };
    }

    if (!mediaIds.includes(id)) mediaIds.push(id);
  }

  const plain = html.replace(/<[^>]*>/g, '').replace(/&nbsp;/g, ' ').trim();
  if (!plain && !mediaIds.length) {
    return { error: 'Write something or attach a file' };
  }

  return { title, html, mediaIds };
}

function serveNewsMedia(req, res, rec) {
  const filePath = path.join(NEWS_DIR, rec.filename);
  let stat;

  try {
    stat = fs.statSync(filePath);
  } catch (_) {
    return send(res, 404, { error: 'The file is missing on the server' });
  }

  const total = stat.size;
  const headers = {
    'Content-Type': rec.mimeType,
    'Accept-Ranges': 'bytes',
    'Cache-Control': 'private, max-age=3600',
    'X-Content-Type-Options': 'nosniff',
    'Content-Disposition': mediaDisposition(rec)
  };

  let start = 0;
  let end = total - 1;
  let status = 200;
  const range = req.headers.range;

  if (range) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(String(range).trim());
    if (!m || (m[1] === '' && m[2] === '')) {
      res.writeHead(416, { 'Content-Range': 'bytes */' + total });
      return res.end();
    }

    if (m[1] === '') {
      start = Math.max(total - Number(m[2]), 0);
    } else {
      start = Number(m[1]);
      if (m[2] !== '') end = Math.min(Number(m[2]), total - 1);
    }

    if (start > end || start >= total) {
      res.writeHead(416, { 'Content-Range': 'bytes */' + total });
      return res.end();
    }

    status = 206;
    headers['Content-Range'] = 'bytes ' + start + '-' + end + '/' + total;
  }

  headers['Content-Length'] = end - start + 1;
  res.writeHead(status, headers);

  const stream = fs.createReadStream(filePath, { start, end });
  stream.on('error', () => res.destroy());
  res.on('close', () => stream.destroy());
  stream.pipe(res);
}

function socialMediaView(rec) {
  if (!rec) return null;
  return { id: rec.id, kind: rec.kind, mimeType: rec.mimeType, name: rec.name,
    size: rec.size, url: '/social/media/' + rec.id };
}

function serveSocialMedia(req, res, rec) {
  const filePath = path.join(UPLOAD_DIR, rec.filename);
  let stat;
  try { stat = fs.statSync(filePath); }
  catch (_) { return send(res, 404, { error: 'The media file is missing on the server' }); }
  const total = stat.size;
  const headers = {
    'Content-Type': rec.mimeType, 'Accept-Ranges': 'bytes',
    'Cache-Control': 'private, max-age=3600', 'X-Content-Type-Options': 'nosniff',
    'Content-Disposition': mediaDisposition(rec)
  };
  let start = 0, end = total - 1, status = 200;
  const range = req.headers.range;
  if (range) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(String(range).trim());
    if (!m || (m[1] === '' && m[2] === '')) {
      res.writeHead(416, { 'Content-Range': 'bytes */' + total }); return res.end();
    }
    if (m[1] === '') start = Math.max(total - Number(m[2]), 0);
    else { start = Number(m[1]); if (m[2] !== '') end = Math.min(Number(m[2]), total - 1); }
    if (start > end || start >= total) {
      res.writeHead(416, { 'Content-Range': 'bytes */' + total }); return res.end();
    }
    status = 206;
    headers['Content-Range'] = 'bytes ' + start + '-' + end + '/' + total;
  }
  headers['Content-Length'] = end - start + 1;
  res.writeHead(status, headers);
  const stream = fs.createReadStream(filePath, { start, end });
  stream.on('error', () => res.destroy());
  res.on('close', () => stream.destroy());
  stream.pipe(res);
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const route = `${req.method} ${url.pathname}`;
  const ip = (req.socket.remoteAddress || '').replace('::ffff:', '');

  if (req.method === 'GET' && ['/snd/server_cert.pem', '/sgn/snd/server_cert.pem'].includes(url.pathname)) {
    const pem = SKYGLOW_TLS_CERT;
    res.writeHead(200, { 'Content-Type': 'application/x-pem-file', 'Content-Length': Buffer.byteLength(pem), 'Cache-Control': 'public, max-age=31536000', 'X-Content-Type-Options': 'nosniff' });
    return res.end(pem);
  }

  if (route === 'GET /sgn/health' || route === 'GET /sgn/' || route === 'GET /sgn') {
    return send(res, 200, { ok: true, service: 'Skyglow Notifications', serverAddress: SKYGLOW_SERVER_ADDRESS, tcpPort: PORT, connectedDevices: skyglowConnections.size });
  }

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
    });

    return res.end();
  }

  if (route === 'GET /health') {
    return send(res, 200, {
      ok: true,
      name: 'iLegacy',
      users: Object.keys(db.users).length,
      messages: db.messages.length,
      posts: db.posts.length,
      time: new Date().toISOString()
    });
  }

  if (route === 'GET /logs/stream') {
    if (ip !== '127.0.0.1' && ip !== '::1') {
      return send(res, 403, {
        error: 'Logs are only viewable from the host PC'
      });
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive'
    });

    res.write('data: --- live log connected ---\n\n');
    logViewers.add(res);
    req.on('close', () => logViewers.delete(res));
    return;
  }

  if (route === 'POST /register') {
    if (tooManyAttempts(ip)) {
      return send(res, 429, {
        error: 'Too many attempts. Wait a minute.'
      });
    }

    const { username, password, displayName } = await readJson(req);
    if (!validUsername(username)) {
      return send(res, 400, {
        error: 'Username must be 3-20 characters: letters, numbers, underscore'
      });
    }

    if (
      typeof password !== 'string' ||
      password.length < 8 ||
      password.length > 128
    ) {
      return send(res, 400, {
        error: 'Password must be 8-128 characters'
      });
    }

    if (db.usernames[username.toLowerCase()]) return send(res, 409, { error: 'Username already taken' });

    const salt = crypto.randomBytes(16).toString('hex');
    const user = {
      userId: newUserId(),
      username,
      displayName:
        (typeof displayName === 'string' &&
          displayName.trim().slice(0, 40)) || username,
      salt,
      passHash: hashPassword(password, salt),
      createdAt: new Date().toISOString()
    };

    db.users[user.userId] = user;
    db.usernames[username.toLowerCase()] = user.userId;
    db.profiles[user.userId] = {
      bio: '',
      bgColor: '#f0f2f5',
      avatar: null,
      invisible: false,
      createdAt: Date.now()
    };

    const token = newToken();
    db.sessions[token] = {
      userId: user.userId,
      createdAt: Date.now()
    };

    saveDb();
    log('ACCOUNT', `Created ${user.userId} (@${username}) from ${ip}`);
    return send(res, 201, {
      user: publicUser(user),
      token
    });
  }

  if (route === 'POST /login') {
    if (tooManyAttempts(ip)) {
      return send(res, 429, {
        error: 'Too many attempts. Wait a minute.'
      });
    }

    const { userId, username, password } = await readJson(req);
    const id = userId ||
      (typeof username === 'string'
        ? db.usernames[username.toLowerCase()]
        : null);
    const user = id ? db.users[id] : null;
    if (!user || typeof password !== 'string') {
      log('AUTH', `Failed login from ${ip}`);
      return send(res, 401, {
        error: 'Wrong ID/username or password'
      });
    }

    const actual = Buffer.from(hashPassword(password, user.salt), 'hex');
    const expected = Buffer.from(user.passHash, 'hex');
    if (
      actual.length !== expected.length ||
      !crypto.timingSafeEqual(actual, expected)
    ) {
      log('AUTH', `Failed login for ${user.userId} from ${ip}`);
      return send(res, 401, {
        error: 'Wrong ID/username or password'
      });
    }

    const token = newToken();
    db.sessions[token] = {
      userId: user.userId,
      createdAt: Date.now()
    };

    saveDb();
    log('AUTH', `Login ${user.userId} from ${ip}`);
    return send(res, 200, {
      user: publicUser(user),
      token
    });
  }

  const me = authUser(req, url);

  if (!me) return send(res, 401, { error: 'Not logged in' });

  if (route === 'GET /SkyNotifications/registration-certificate') {
    if (!isAdmin(me)) return send(res, 403, { error: 'Moderator access required' });
    const pem = SKYGLOW_TLS_CERT;
    res.writeHead(200, {
      'Content-Type': 'application/x-pem-file',
      'Content-Length': Buffer.byteLength(pem),
      'Content-Disposition': 'attachment; filename="ilegacy-skyglow-server-cert.pem"',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    });
    return res.end(pem);
  }

  if (route === 'POST /SkyNotifications/register') {
    let body;
    try { body = await readJson(req); } catch (_) {
      return send(res, 400, { error: 'Invalid request body' });
    }
    const deviceToken = typeof body.deviceToken === 'string' ? body.deviceToken.toLowerCase() : '';
    const bundleId = typeof body.bundleId === 'string' ? body.bundleId : '';
    if (!/^[a-f0-9]{64}$/.test(deviceToken)) {
      return send(res, 400, { error: 'Skyglow device token must be 32 bytes (64 hex characters)' });
    }
    if (bundleId !== 'com.ilegacy.app') return send(res, 400, { error: 'Unsupported application bundle ID' });
    if (!db.skyglowTokens || typeof db.skyglowTokens !== 'object') db.skyglowTokens = {};
    db.skyglowTokens[me.userId] = {
      deviceToken,
      bundleId,
      updatedAt: Date.now()
    };
    saveDb();
    log('SKYGLOW', `Registered a device token for ${me.userId}`);
    return send(res, 200, { ok: true, registered: true, provider: 'skyglow' });
  }

  if (route === 'DELETE /SkyNotifications/register') {
    if (db.skyglowTokens) delete db.skyglowTokens[me.userId];
    saveDb();
    return send(res, 200, { ok: true, registered: false });
  }

  if (route === 'GET /SkyNotifications/status') {
    const entry = db.skyglowTokens && db.skyglowTokens[me.userId];
    return send(res, 200, { ok: true, registered: !!(entry && entry.deviceToken), provider: 'skyglow', senderConfigured: !!SKYGLOW_HTTP_API_URL });
  }

  if (route === 'POST /SkyNotifications/test') {
    const entry = db.skyglowTokens && db.skyglowTokens[me.userId];
    if (!entry || !/^[a-f0-9]{64}$/i.test(entry.deviceToken || '')) {
      return send(res, 409, { ok: false, error: 'No Skyglow device token is registered yet. Open Notification Services and allow Skyglow registration first.' });
    }
    const payload = {
      aps: { alert: { title: 'iLegacy', body: 'Testing from iLegacy!' }, sound: 'default' },
      app: 'com.ilegacy.app',
      event: 'notification',
      notification_id: 'ilegacy-test-' + Date.now()
    };
    const queued = sgnQueueFromToken(entry.deviceToken, payload);
    if (!queued) {
      return send(res, 502, { ok: false, error: 'The token could not be routed by this Skyglow server. Check the active Skyglow profile and server address.' });
    }
    log('SKYGLOW', 'Queued test notification for ' + me.userId);
    return send(res, 200, { ok: true, queued: true, provider: 'skyglow', message: 'Testing from iLegacy!' });
  }

  if (route === 'GET /calls/config') {
    const iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];
    if (ILEGACY_TURN_URL && ILEGACY_TURN_SHARED_SECRET) {
      const expires = Math.floor(Date.now() / 1000) + ILEGACY_TURN_TTL_SECONDS;
      const username = `${expires}:${me.userId}`;
      const credential = crypto.createHmac('sha1', ILEGACY_TURN_SHARED_SECRET)
        .update(username).digest('base64');
      iceServers.push({
        urls: ILEGACY_TURN_URL,
        username,
        credential
      });
    }
    return send(res, 200, { iceServers });
  }

  if (route === 'POST /calls/invite') {
    let body;
    try { body = await readJson(req); } catch (_) {
      return send(res, 400, { error: 'Invalid request body' });
    }
    const to = typeof body.to === 'string' ? body.to.trim() : '';
    if (!to || !db.users[to] || to === me.userId) {
      return send(res, 400, { error: 'Choose a valid other iLegacy user' });
    }
    if (callForUser(me.userId)) return send(res, 409, { error: 'You are already in a call' });
    if (callForUser(to)) return send(res, 409, { error: 'That user is already in a call' });

    const call = {
      id: crypto.randomUUID(),
      from: me.userId,
      to,
      createdAt: Date.now(),
      timeout: null
    };
    call.timeout = setTimeout(() => finishCall(call.id, null, 'timeout'), CALL_RING_TIMEOUT_MS);
    activeCalls.set(call.id, call);
    pushToUser(to, 'call_invite', {
      callId: call.id,
      from: publicUser(me),
      createdAt: call.createdAt
    });
    log('CALL', `${me.userId} invited ${to}`);
    return send(res, 201, { call: publicCall(call) });
  }

  const callAction = url.pathname.match(/^\/calls\/([a-f0-9-]{36})\/(accept|decline|signal|end)$/);
  if (callAction && req.method === 'POST') {
    const callId = callAction[1];
    const action = callAction[2];
    const call = activeCalls.get(callId);
    if (!call) return send(res, 404, { error: 'Call no longer exists' });
    if (call.from !== me.userId && call.to !== me.userId) {
      return send(res, 403, { error: 'You are not a participant in this call' });
    }

    if (action === 'accept') {
      if (me.userId !== call.to) return send(res, 403, { error: 'Only the recipient can answer' });
      clearTimeout(call.timeout);
      call.timeout = null;
      pushToUser(call.from, 'call_accepted', { callId: call.id, by: me.userId });
      log('CALL', `${me.userId} answered call ${call.id}`);
      return send(res, 200, { ok: true, call: publicCall(call) });
    }

    if (action === 'decline') {
      if (me.userId !== call.to) return send(res, 403, { error: 'Only the recipient can decline' });
      finishCall(call.id, me.userId, 'declined');
      return send(res, 200, { ok: true });
    }

    if (action === 'end') {
      finishCall(call.id, me.userId, 'ended');
      return send(res, 200, { ok: true });
    }

    let body;
    try { body = await readJson(req); } catch (_) {
      return send(res, 400, { error: 'Invalid request body' });
    }
    const signal = body.signal;
    if (!signal || typeof signal !== 'object' ||
        Buffer.byteLength(JSON.stringify(signal), 'utf8') > CALL_SIGNAL_MAX_BYTES) {
      return send(res, 400, { error: 'Invalid or oversized call signal' });
    }
    const other = call.from === me.userId ? call.to : call.from;
    pushToUser(other, 'call_signal', { callId: call.id, from: me.userId, signal });
    return send(res, 200, { ok: true });
  }

  if (route === 'POST /logout') {
    const token = getToken(req, url);
    delete db.sessions[token];
    saveDb();
    log('AUTH', `Logout ${me.userId}`);
    return send(res, 200, { ok: true });
  }

  if (route === 'GET /me') return send(res, 200, { user: publicUser(me) });

  if (req.method === 'GET' && url.pathname.startsWith('/users/')) {
    let id;
    try {
      id = decodeURIComponent(url.pathname.slice('/users/'.length));
    } catch {
      return send(res, 400, { error: 'Invalid user ID' });
    }

    const target = db.users[id];
    if (!target) return send(res, 404, { error: 'No such user' });

    return send(res, 200, { user: publicUser(target) });
  }

  if (route === 'POST /social/media') {
    const scope = url.searchParams.get('scope');
    const to = url.searchParams.get('to') || '';
    if (scope !== 'dm' && scope !== 'post') {
      req.resume(); return send(res, 400, { error: 'scope must be dm or post' });
    }
    if (scope === 'dm' && (!to || !db.users[to] || to === me.userId)) {
      req.resume(); return send(res, 400, { error: 'A valid DM recipient is required' });
    }
    const declared = Number(req.headers['content-length']);
    if (declared > NEWS_LIMITS.video) {
      req.resume(); return send(res, 413, { error: 'File too large' });
    }
    const name = path.basename(cleanText(url.searchParams.get('name'), 120)) || 'attachment';
    const id = crypto.randomUUID();
    const tmpPath = path.join(UPLOAD_DIR, id + '.part');
    let received;
    try { received = await receiveNewsMedia(req, tmpPath, { allowZip: scope === 'dm' }); }
    catch (err) { return send(res, 400, { error: err.message || 'Unsupported media file' }); }
    const filename = id + received.ext;
    try { fs.renameSync(tmpPath, path.join(UPLOAD_DIR, filename)); }
    catch (err) {
      log('ERROR', 'Social media save failed: ' + err.message);
      try { fs.unlinkSync(tmpPath); } catch (_) {}
      return send(res, 500, { error: 'Could not save the media file on the server computer' });
    }
    const rec = {
      id, kind: received.kind, mimeType: received.mimeType, size: received.size,
      name, filename, uploadedBy: me.userId, scope, to: scope === 'dm' ? to : null,
      ts: Date.now(), messageId: null, postId: null
    };
    if (!db.socialMedia || typeof db.socialMedia !== 'object') db.socialMedia = {};
    db.socialMedia[id] = rec;
    saveDbImmediately();
    log('MEDIA', me.userId + ' uploaded ' + received.kind + ' for ' + scope +
      ' (' + received.size + ' bytes)');
    return send(res, 201, { media: socialMediaView(rec) });
  }

  const socialMediaGet = req.method === 'GET' &&
    url.pathname.match(/^\/social\/media\/([a-f0-9-]{36})$/);
  if (socialMediaGet) {
    const rec = db.socialMedia && db.socialMedia[socialMediaGet[1]];
    if (!rec) return send(res, 404, { error: 'No such media file' });
    let allowed = false;
    if (rec.scope === 'post') {
      allowed = !!rec.postId && db.posts.some((post) => post.id === rec.postId);
    } else if (rec.scope === 'dm') {
      const msg = rec.messageId && db.messages.find((item) => item.id === rec.messageId);
      allowed = !!msg && (msg.from === me.userId || msg.to === me.userId);
    }
    if (!allowed) return send(res, 404, { error: 'Media not found' });
    return serveSocialMedia(req, res, rec);
  }

  if (route === 'POST /messages') {
    const body = await readJson(req);
    const to = body.to;
    const text = typeof body.text === 'string' ? body.text.trim() : '';
    const hasImage = body.imageData !== undefined && body.imageData !== null &&
      body.imageData !== '';
    const mediaRec = (body.mediaId && db.socialMedia) ? db.socialMedia[body.mediaId] : null;
    const hasMedia = !!mediaRec;
    if (typeof to !== 'string' || !db.users[to]) return send(res, 404, { error: 'Recipient does not exist' });

    if (to === me.userId) return send(res, 400, { error: 'You cannot send a DM to yourself' });

    if (text.length > ((hasImage || hasMedia) ? MAX_CAPTION_LEN : MAX_MESSAGE_LEN)) {
      return send(res, 400, {
        error: (hasImage || hasMedia)
          ? `Attachment caption must be ${MAX_CAPTION_LEN} characters or fewer`
          : `Message must be 1-${MAX_MESSAGE_LEN} characters`
      });
    }
    if (!text && !hasImage && !hasMedia) return send(res, 400, { error: 'Write a message or choose an attachment' });
    if (hasMedia && (mediaRec.scope !== 'dm' || mediaRec.uploadedBy !== me.userId ||
        mediaRec.to !== to || mediaRec.messageId)) {
      return send(res, 400, { error: 'That attachment is not available for this conversation' });
    }

    const msg = {
      id: crypto.randomUUID(),
      from: me.userId,
      to,
      text,
      ts: Date.now(),
      deliveredAt: null,
      readAt: null
    };

    if (hasImage) {
      const img = social.readImage(body.mimeType, body.imageData);
      if (img.error) return send(res, 400, { error: img.error });

      const filename = crypto.randomUUID() + img.type.extension;
      try {
        fs.writeFileSync(path.join(UPLOAD_DIR, filename), img.buffer, { flag: 'wx' });
      } catch (err) {
        log('ERROR', 'DM image save failed: ' + err.message);
        return send(res, 500, { error: 'Could not save image on the server computer' });
      }

      msg.type = 'image';
      msg.filename = filename;
      msg.mimeType = body.mimeType;
    } else if (hasMedia) {
      msg.type = 'media';
      msg.mediaId = mediaRec.id;
      msg.mediaKind = mediaRec.kind;
      msg.mimeType = mediaRec.mimeType;
      msg.mediaName = mediaRec.name;
      msg.mediaSize = mediaRec.size;
      msg.filename = mediaRec.filename;
      mediaRec.messageId = msg.id;
    } else {
      msg.type = 'text';
    }

    db.messages.push(msg);
    saveDb();
    pushToUser(to, 'message', msg);
    pushToUser(me.userId, 'message', msg);
    log('MESSAGE', `${me.userId} -> ${to} (${
      msg.type === 'image' ? 'image' : (msg.type === 'media' ? mediaRec.kind : text.length + ' chars')
    })`);
    return send(res, 201, { message: msg });
  }

  if (req.method === 'GET' && url.pathname.startsWith('/dm-uploads/')) {
    let filename;
    try {
      filename = decodeURIComponent(url.pathname.slice('/dm-uploads/'.length));
    } catch {
      return send(res, 400, { error: 'Invalid image path' });
    }

    if (!filename || path.basename(filename) !== filename ||
        !/^[a-f0-9-]+\.(jpg|png|gif|webp)$/.test(filename)) {
      return send(res, 400, { error: 'Invalid image path' });
    }

    const msg = db.messages.find((m) => m.type === 'image' && m.filename === filename);
    if (!msg || (msg.from !== me.userId && msg.to !== me.userId)) return send(res, 404, { error: 'Image not found' });

    const filePath = path.join(UPLOAD_DIR, filename);
    if (!fs.existsSync(filePath)) return send(res, 404, { error: 'Image file is missing' });

    const mime = {
      '.jpg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.webp': 'image/webp'
    }[path.extname(filename)];
    res.writeHead(200, {
      'Content-Type': mime,
      'Content-Length': fs.statSync(filePath).size,
      'Cache-Control': 'private, max-age=3600',
      'X-Content-Type-Options': 'nosniff'
    });
    return fs.createReadStream(filePath).pipe(res);
  }

  if (route === 'POST /messages/read') {
    const body = await readJson(req);
    const other = body.with;
    if (typeof other !== 'string' || !db.users[other]) {
      return send(res, 400, { error: 'A valid conversation user is required' });
    }

    const now = Date.now();
    let changed = false;
    for (const msg of db.messages) {
      if (msg.from === other && msg.to === me.userId && !msg.readAt) {
        msg.deliveredAt = msg.deliveredAt || now;
        msg.readAt = now;
        changed = true;
        pushToUser(msg.from, 'message_status', {
          id: msg.id, deliveredAt: msg.deliveredAt, readAt: msg.readAt
        });
      }
    }

    if (changed) saveDb();
    return send(res, 200, { ok: true });
  }

  if (route === 'GET /messages') {
    const other = url.searchParams.get('with');
    const since = Number(url.searchParams.get('since') || 0);
    if (!other) return send(res, 400, { error: 'Missing ?with=USERID' });
    if (!db.users[other]) return send(res, 404, { error: 'No such user' });

    const now = Date.now();
    let changed = false;
    for (const msg of db.messages) {
      if (msg.from === other && msg.to === me.userId && !msg.deliveredAt) {
        msg.deliveredAt = now;
        changed = true;
        pushToUser(msg.from, 'message_status', {
          id: msg.id, deliveredAt: msg.deliveredAt, readAt: msg.readAt || null
        });
      }
    }
    if (changed) saveDb();
    const messages = db.messages
      .filter((m) =>
        m.ts > since &&
        ((m.from === me.userId && m.to === other) ||
         (m.from === other && m.to === me.userId))
      )
      .slice(-200);
    return send(res, 200, { messages });
  }

  if (route === 'GET /conversations') {
    const latest = new Map();
    for (const msg of db.messages) {
      if (msg.from !== me.userId && msg.to !== me.userId) continue;
      const other = msg.from === me.userId ? msg.to : msg.from;
      latest.set(other, msg);
    }

    const conversations = [...latest.entries()]
      .filter(([other]) => db.users[other])
      .map(([other, last]) => ({
        with: publicUser(db.users[other]),
        last
      }))
      .sort((a, b) => b.last.ts - a.last.ts);
    return send(res, 200, { conversations });
  }

  if (route === 'GET /stream') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    });

    res.write('event: ready\ndata: {}\n\n');
    if (!liveClients.has(me.userId)) {
      liveClients.set(me.userId, new Set());
    }

    liveClients.get(me.userId).add(res);
    if (liveClients.get(me.userId).size === 1) broadcastPresence(me.userId);
    log(
      'STREAM',
      `${me.userId} connected live (${liveClients.get(me.userId).size} device(s))`
    );
    req.on('close', () => {
      const clients = liveClients.get(me.userId);
      if (clients) {
        clients.delete(res);
        if (!clients.size) liveClients.delete(me.userId);
      }

      log('STREAM', `${me.userId} disconnected`);
      schedulePresenceCheck(me.userId);
    });
    return;
  }

  if (await social.handle(req, res, url, me, getToken(req, url))) return;

  const historyMatch = req.method === 'GET' &&
    url.pathname.match(/^\/admin\/users\/([^/]+)\/history$/);

  if (historyMatch) {
    if (!isAdmin(me)) return send(res, 403, { error: 'Admin access required' });

    let id;
    try {
      id = decodeURIComponent(historyMatch[1]);
    } catch {
      return send(res, 400, { error: 'Invalid user ID' });
    }

    const target = db.users[id];
    if (!target) return send(res, 404, { error: 'No such user' });

    const inboxAll = db.notifications
      .filter((n) => n.userId === id)
      .sort((a, b) => b.ts - a.ts);
    const inbox = inboxAll.slice(0, 1000).map((n) => ({
      id: n.id,
      type: n.type,
      from: userBrief(n.from),
      text: n.text || null,
      reason: n.reason || null,
      ts: n.ts,
      read: !!n.read
    }));
    const downloadsAll = db.downloadLog
      .filter((d) => d.userId === id)
      .sort((a, b) => b.ts - a.ts);
    const downloads = downloadsAll.slice(0, 1000).map((d) => ({
      id: d.id,
      name: d.name,
      bundleId: d.bundleId,
      version: d.version,
      ts: d.ts,
      stillAvailable: db.debs.some((x) => x.id === d.debId)
    }));
    const uploadsAll = db.uploadLog
      .filter((u) => u.userId === id)
      .sort((a, b) => b.ts - a.ts);
    const uploads = uploadsAll.slice(0, 1000).map((u) => ({
      id: u.id,
      name: u.name,
      bundleId: u.bundleId,
      version: u.version,
      size: u.size,
      ts: u.ts,
      stillAvailable: db.debs.some((x) => x.id === u.debId)
    }));
    const dmAll = db.messages
      .filter((m) => m.from === id || m.to === id)
      .sort((a, b) => b.ts - a.ts);
    const dms = dmAll.slice(0, 2000).map((m) => ({
      id: m.id,
      from: userBrief(m.from),
      to: userBrief(m.to),
      direction: m.from === id ? 'sent' : 'received',
      type: m.type === 'image' ? 'image' : (m.type === 'media' ? (m.mediaKind || 'media') : 'text'),
      ts: m.ts,
      deliveredAt: m.deliveredAt || null,
      readAt: m.readAt || null
    }));
    log('MODERATION', `${me.userId} viewed the account history of ${id}`);
    return send(res, 200, {
      user: publicUser(target),
      counts: {
        inbox: inboxAll.length,
        downloads: downloadsAll.length,
        uploads: uploadsAll.length,
        dms: dmAll.length
      },
      inbox,
      downloads,
      uploads,
      dms
    });
  }

  if (route === 'GET /downloads') {
    return send(res, 200, {
      categories: downloadsOverview(),
      canManage: isAdmin(me),
      tags: DEB_TAGS
    });
  }

  if (route === 'POST /downloads/categories') {
    if (!isAdmin(me)) return send(res, 403, { error: 'Admin access required' });

    const body = await readJson(req);
    const name = cleanText(body.name, MAX_CATEGORY_NAME);
    if (!name) return send(res, 400, { error: 'Enter a category name' });

    if (db.downloadCategories.length >= MAX_CATEGORIES) return send(res, 400, { error: 'Too many categories' });

    if (db.downloadCategories.some(
      (c) => c.name.toLowerCase() === name.toLowerCase()
    )) {
      return send(res, 409, { error: 'That category already exists' });
    }

    const category = {
      id: crypto.randomUUID(),
      name,
      createdAt: Date.now(),
      createdBy: me.userId
    };

    db.downloadCategories.push(category);
    saveDbImmediately();
    log('DOWNLOADS', `${me.userId} created category "${name}"`);
    return send(res, 201, {
      category: { id: category.id, name: category.name, createdAt: category.createdAt, debs: [] }
    });
  }

  const dlCategoryDelete = req.method === 'POST' &&
    url.pathname.match(/^\/downloads\/categories\/([a-f0-9-]{36})\/delete$/);

  if (dlCategoryDelete) {
    if (!isAdmin(me)) return send(res, 403, { error: 'Admin access required' });

    const category = db.downloadCategories.find((c) => c.id === dlCategoryDelete[1]);
    if (!category) return send(res, 404, { error: 'No such category' });

    const doomed = db.debs.filter((d) => d.categoryId === category.id);
    doomed.forEach(removeDebFile);
    db.debs = db.debs.filter((d) => d.categoryId !== category.id);
    db.downloadCategories = db.downloadCategories.filter((c) => c.id !== category.id);
    saveDbImmediately();
    log('DOWNLOADS', `${me.userId} deleted category "${category.name}" (${doomed.length} files)`);
    return send(res, 200, { ok: true });
  }

  if (route === 'POST /downloads/debs') {
    if (!isAdmin(me)) {
      req.resume();
      return send(res, 403, { error: 'Admin access required' });
    }

    const q = url.searchParams;
    const category = db.downloadCategories.find((c) => c.id === q.get('categoryId'));
    const name = cleanText(q.get('name'), 80);
    const author = cleanText(q.get('author'), 60);
    const bundleId = cleanText(q.get('bundleId'), 150);
    const version = cleanText(q.get('version'), 50);
    const minIOS = cleanText(q.get('minIOS'), 12);
    const maxIOS = cleanText(q.get('maxIOS'), 12);
    const description = cleanText(q.get('description'), 500);
    const tag = cleanText(q.get('tag'), 30);
    const iosPattern = /^\d+(\.\d+){0,2}$/;
    let problem = '';
    if (!category) problem = 'Choose a category';
    else if (!name) problem = 'Package name is required';
    else if (!author) problem = 'Author is required';
    else if (!/^[A-Za-z0-9][A-Za-z0-9.+_-]{1,149}$/.test(bundleId)) {
      problem = 'Bundle ID may only use letters, numbers, dots, dashes, plus and underscore';
    } else if (!/^[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,49}$/.test(version)) {
      problem = 'Enter a valid version number (for example 1.0.2)';
    } else if (minIOS && !iosPattern.test(minIOS)) {
      problem = 'Minimum iOS must look like 6.0 or 6.1.3';
    } else if (maxIOS && !iosPattern.test(maxIOS)) {
      problem = 'Maximum iOS must look like 6.0 or 6.1.3';
    } else if (tag && !DEB_TAGS.includes(tag)) {
      problem = 'Unknown tag';
    } else if (db.debs.some((d) =>
      d.categoryId === category.id &&
      d.bundleId.toLowerCase() === bundleId.toLowerCase() &&
      d.version === version)) {
      problem = 'That bundle ID and version is already in this category';
    }

    if (problem) {
      req.resume();
      return send(res, 400, { error: problem });
    }

    const declared = Number(req.headers['content-length']);
    if (declared > MAX_DEB_BYTES) {
      req.resume();
      return send(res, 413, { error: 'File too large. Maximum size is 200 MB.' });
    }

    let fileName = path.basename(cleanText(q.get('fileName'), 120))
      .replace(/[^A-Za-z0-9._+-]/g, '_');
    const fileExt = /\.exe$/i.test(fileName) ? '.exe' : '.deb';
    if (!/\.(deb|exe)$/i.test(fileName)) {
      fileName = (bundleId + '_' + version).replace(/[^A-Za-z0-9._+-]/g, '_') + fileExt;
    }

    const id = crypto.randomUUID();
    const storedName = id + fileExt;
    const tmpPath = path.join(DEB_DIR, id + '.part');
    const received = await receiveDeb(req, tmpPath, fileExt);
    try {
      fs.renameSync(tmpPath, path.join(DEB_DIR, storedName));
    } catch (err) {
      log('ERROR', 'Upload save failed: ' + err.message);
      try { fs.unlinkSync(tmpPath); } catch (_) {}
      return send(res, 500, { error: 'Could not save the file on the server computer' });
    }

    const deb = {
      id,
      categoryId: category.id,
      name,
      author,
      bundleId,
      version,
      description,
      minIOS,
      maxIOS,
      tag,
      fileName,
      filename: storedName,
      size: received.size,
      sha256: received.sha256,
      downloads: 0,
      uploadedBy: me.userId,
      uploadedAt: Date.now()
    };

    db.debs.push(deb);
    logUpload(deb);
    saveDbImmediately();
    log(
      'DOWNLOADS',
      `${me.userId} uploaded ${bundleId} ${version} to "${category.name}" (${received.size} bytes)`
    );
    return send(res, 201, { deb: debView(deb) });
  }

  const dlDebEdit = req.method === 'POST' &&
    url.pathname.match(/^\/downloads\/debs\/([a-f0-9-]{36})\/edit$/);

  if (dlDebEdit) {
    if (!isAdmin(me)) return send(res, 403, { error: 'Admin access required' });

    const deb = db.debs.find((d) => d.id === dlDebEdit[1]);
    if (!deb) return send(res, 404, { error: 'No such file' });

    const body = await readJson(req);
    const pick = (key, max, current) =>
      body[key] !== undefined ? cleanText(body[key], max) : (current || '');
    const category = db.downloadCategories.find(
      (c) => c.id === (body.categoryId !== undefined ? body.categoryId : deb.categoryId)
    );
    const name = pick('name', 80, deb.name);
    const author = pick('author', 60, deb.author);
    const bundleId = pick('bundleId', 150, deb.bundleId);
    const version = pick('version', 50, deb.version);
    const minIOS = pick('minIOS', 12, deb.minIOS);
    const maxIOS = pick('maxIOS', 12, deb.maxIOS);
    const description = pick('description', 500, deb.description);
    const tag = pick('tag', 30, deb.tag);
    const iosPattern = /^\d+(\.\d+){0,2}$/;
    let problem = '';
    if (!category) problem = 'Choose a category';
    else if (!name) problem = 'Package name is required';
    else if (!author) problem = 'Author is required';
    else if (!/^[A-Za-z0-9][A-Za-z0-9.+_-]{1,149}$/.test(bundleId)) {
      problem = 'Bundle ID may only use letters, numbers, dots, dashes, plus and underscore';
    } else if (!/^[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,49}$/.test(version)) {
      problem = 'Enter a valid version number (for example 1.0.2)';
    } else if (minIOS && !iosPattern.test(minIOS)) {
      problem = 'Minimum iOS must look like 6.0 or 6.1.3';
    } else if (maxIOS && !iosPattern.test(maxIOS)) {
      problem = 'Maximum iOS must look like 6.0 or 6.1.3';
    } else if (tag && !DEB_TAGS.includes(tag)) {
      problem = 'Unknown tag';
    } else if (db.debs.some((d) =>
      d.id !== deb.id &&
      d.categoryId === category.id &&
      d.bundleId.toLowerCase() === bundleId.toLowerCase() &&
      d.version === version)) {
      problem = 'That bundle ID and version is already in this category';
    }

    if (problem) return send(res, 400, { error: problem });

    deb.categoryId = category.id;
    deb.name = name;
    deb.author = author;
    deb.bundleId = bundleId;
    deb.version = version;
    deb.minIOS = minIOS;
    deb.maxIOS = maxIOS;
    deb.description = description;
    deb.tag = tag;
    deb.editedAt = Date.now();
    deb.editedBy = me.userId;
    saveDbImmediately();
    log('DOWNLOADS', `${me.userId} edited ${deb.bundleId} ${deb.version}` +
      (tag ? ` (tag: ${tag})` : ''));
    return send(res, 200, { deb: debView(deb) });
  }

  const dlDebDelete = req.method === 'POST' &&
    url.pathname.match(/^\/downloads\/debs\/([a-f0-9-]{36})\/delete$/);

  if (dlDebDelete) {
    if (!isAdmin(me)) return send(res, 403, { error: 'Admin access required' });

    const deb = db.debs.find((d) => d.id === dlDebDelete[1]);
    if (!deb) return send(res, 404, { error: 'No such file' });

    removeDebFile(deb);
    db.debs = db.debs.filter((d) => d.id !== deb.id);
    saveDbImmediately();
    log('DOWNLOADS', `${me.userId} deleted ${deb.bundleId} ${deb.version}`);
    return send(res, 200, { ok: true });
  }

  const dlDebFile = req.method === 'GET' &&
    url.pathname.match(/^\/downloads\/debs\/([a-f0-9-]{36})\/file$/);

  if (dlDebFile) {
    const deb = db.debs.find((d) => d.id === dlDebFile[1]);
    if (!deb || !/^[a-f0-9-]+\.(deb|exe)$/.test(deb.filename)) return send(res, 404, { error: 'No such file' });

    const filePath = path.join(DEB_DIR, deb.filename);
    if (!fs.existsSync(filePath)) return send(res, 404, { error: 'The file is missing on the server' });

    deb.downloads = (deb.downloads || 0) + 1;
    logDownload(me.userId, deb);
    saveDb();
    res.writeHead(200, {
      'Content-Type': /\.exe$/.test(deb.filename)
        ? 'application/vnd.microsoft.portable-executable'
        : 'application/vnd.debian.binary-package',
      'Content-Length': fs.statSync(filePath).size,
      'Content-Disposition': 'attachment; filename="' + deb.fileName + '"',
      'Cache-Control': 'private, no-cache',
      'X-Content-Type-Options': 'nosniff'
    });

    const stream = fs.createReadStream(filePath);
    stream.on('error', () => res.destroy());
    return stream.pipe(res);
  }

  const driveQuotaBytes = (userId) => Number(db.driveQuotas[userId]) ||
    (isAdmin(db.users[userId]) ? 35 * 1024 * 1024 * 1024 : 2.5 * 1024 * 1024 * 1024);

  const driveUsedBytes = (userId) => Object.values(db.driveFiles)
    .filter((f) => f.ownerId === userId)
    .reduce((sum, f) => sum + (Number(f.size) || 0), 0);

  const driveInFlight = handle.driveInFlight || (handle.driveInFlight = new Map());
  const driveReservedBytes = (userId) => {
    const uploads = driveInFlight.get(userId);
    if (!uploads) return 0;
    return Array.from(uploads.values()).reduce((sum, n) => sum + n, 0);
  };

  const driveView = (f) => ({
    id: f.id, name: f.name, size: f.size, uploadedAt: f.uploadedAt,
    mimeType: f.mimeType || 'application/octet-stream'
  });

  if (route === 'GET /drive') {
    const files = Object.values(db.driveFiles)
      .filter((f) => f.ownerId === me.userId)
      .sort((a, b) => b.uploadedAt - a.uploadedAt)
      .map(driveView);
    return send(res, 200, {
      files,
      usedBytes: driveUsedBytes(me.userId),
      quotaBytes: driveQuotaBytes(me.userId),
      isModerator: isAdmin(me)
    });
  }

  if (route === 'POST /drive/upload') {
    const rawName = url.searchParams.get('name') || 'file';
    const name = path.basename(rawName).replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 255) || 'file';
    const declared = req.headers['content-length'] === undefined
      ? null : Number(req.headers['content-length']);
    const used = driveUsedBytes(me.userId);
    const quota = driveQuotaBytes(me.userId);
    if (declared !== null && (!Number.isFinite(declared) || declared < 0 ||
        used + driveReservedBytes(me.userId) + declared > quota)) {
      req.resume();
      return send(res, 413, { error: 'Not enough storage space for this file.' });
    }

    const id = crypto.randomUUID();
    const tmpPath = path.join(DRIVE_DIR, id + '.part');
    const finalName = id + '.blob';
    const finalPath = path.join(DRIVE_DIR, finalName);
    const uploads = driveInFlight.get(me.userId) || new Map();
    driveInFlight.set(me.userId, uploads);
    uploads.set(id, 0);
    let size = 0;
    let failed = false;
    const out = fs.createWriteStream(tmpPath, { flags: 'wx' });
    const fail = (status, message) => {
      if (failed) return;
      failed = true;
      uploads.delete(id);
      if (!uploads.size) driveInFlight.delete(me.userId);
      out.destroy();
      fs.unlink(tmpPath, () => {});
      req.resume();
      if (!res.headersSent) send(res, status, { error: message });
      else res.destroy();
    };

    req.on('data', (chunk) => {
      if (failed) return;
      const nextSize = size + chunk.length;
      const activeOther = driveReservedBytes(me.userId) - (uploads.get(id) || 0);
      if (driveUsedBytes(me.userId) + activeOther + nextSize > driveQuotaBytes(me.userId)) {
        return fail(413, 'Storage quota exceeded. Delete files or request more storage.');
      }
      size = nextSize;
      uploads.set(id, size);
      if (!out.write(chunk)) {
        req.pause();
        out.once('drain', () => req.resume());
      }
    });
    req.on('aborted', () => fail(400, 'Upload was interrupted.'));
    req.on('error', () => fail(400, 'Upload failed.'));
    out.on('error', () => fail(500, 'Could not write the file to server storage.'));
    req.on('end', () => {
      if (failed) return;
      out.end(() => {
        if (failed) return;
        try {
          fs.renameSync(tmpPath, finalPath);
          const rec = {
            id, ownerId: me.userId, name, filename: finalName, size,
            mimeType: cleanText(req.headers['content-type'], 120) || 'application/octet-stream',
            uploadedAt: Date.now()
          };
          db.driveFiles[id] = rec;
          uploads.delete(id);
          if (!uploads.size) driveInFlight.delete(me.userId);
          saveDbImmediately();
          log('DRIVE', `${me.userId} uploaded "${name}" (${size} bytes)`);
          return send(res, 201, {
            file: driveView(rec),
            usedBytes: driveUsedBytes(me.userId),
            quotaBytes: driveQuotaBytes(me.userId)
          });
        } catch (err) {
          fail(500, 'Could not save the file to server storage.');
        }
      });
    });
    return;
  }

  const driveDownload = req.method === 'GET' &&
    url.pathname.match(/^\/drive\/files\/([a-f0-9-]{36})\/download$/);
  if (driveDownload) {
    const rec = db.driveFiles[driveDownload[1]];
    if (!rec || rec.ownerId !== me.userId) return send(res, 404, { error: 'No such file' });
    const filePath = path.join(DRIVE_DIR, rec.filename);
    let stat;
    try { stat = fs.statSync(filePath); }
    catch (_) { return send(res, 404, { error: 'File is missing from server storage' }); }
    const safeName = String(rec.name || 'file').replace(/["\\\r\n]/g, '_');
    res.writeHead(200, {
      'Content-Type': rec.mimeType || 'application/octet-stream',
      'Content-Length': stat.size,
      'Content-Disposition': 'attachment; filename="' + safeName + '"; filename*=UTF-8\'\'' + encodeURIComponent(rec.name || 'file'),
      'Cache-Control': 'private, no-cache',
      'X-Content-Type-Options': 'nosniff'
    });
    const stream = fs.createReadStream(filePath);
    stream.on('error', () => res.destroy());
    return stream.pipe(res);
  }

  const driveDelete = req.method === 'POST' &&
    url.pathname.match(/^\/drive\/files\/([a-f0-9-]{36})\/delete$/);
  if (driveDelete) {
    const rec = db.driveFiles[driveDelete[1]];
    if (!rec || rec.ownerId !== me.userId) return send(res, 404, { error: 'No such file' });
    try { fs.unlinkSync(path.join(DRIVE_DIR, rec.filename)); }
    catch (err) {
      if (err.code !== 'ENOENT') return send(res, 500, { error: 'Could not delete the file' });
    }
    delete db.driveFiles[rec.id];
    saveDbImmediately();
    log('DRIVE', `${me.userId} deleted "${rec.name}" (${rec.size} bytes)`);
    return send(res, 200, {
      ok: true, usedBytes: driveUsedBytes(me.userId), quotaBytes: driveQuotaBytes(me.userId)
    });
  }

  if (route === 'POST /drive/quota') {
    if (!isAdmin(me)) return send(res, 403, { error: 'Moderator access required' });
    const body = await readJson(req);
    const targetId = typeof body.userId === 'string' ? body.userId.trim().toUpperCase() : '';
    const quotaBytes = Number(body.quotaBytes);
    if (!targetId) return send(res, 400, { error: 'Enter a user ID.' });
    const minQuota = 500 * 1024 * 1024;
    const maxQuota = 75 * 1024 * 1024 * 1024;
    if (!db.users[targetId]) return send(res, 404, { error: 'No such user ID' });
    if (!Number.isFinite(quotaBytes) || quotaBytes < minQuota || quotaBytes > maxQuota) {
      return send(res, 400, { error: 'Storage must be between 500 MB and 75 GB.' });
    }
    if (isAdmin(db.users[targetId]) && targetId !== me.userId) {
      return send(res, 400, { error: "You cannot change another moderator's storage quota." });
    }
    if (driveUsedBytes(targetId) > quotaBytes) {
      return send(res, 400, { error: 'That user already has more files stored than this quota allows.' });
    }
    db.driveQuotas[targetId] = Math.floor(quotaBytes);
    saveDbImmediately();
    log('DRIVE', `${me.userId} set ${targetId} storage quota to ${Math.floor(quotaBytes)} bytes`);
    return send(res, 200, {
      ok: true, userId: targetId, quotaBytes: driveQuotaBytes(targetId),
      usedBytes: driveUsedBytes(targetId)
    });
  }

  if (route === 'GET /news') {
    const items = db.news
      .slice()
      .sort((a, b) => b.ts - a.ts)
      .slice(0, 100)
      .map(newsView);
    return send(res, 200, { news: items, canManage: isAdmin(me) });
  }

  if (route === 'POST /news/media') {
    if (!isAdmin(me)) {
      req.resume();
      return send(res, 403, { error: 'Admin access required' });
    }

    const declared = Number(req.headers['content-length']);
    if (declared > NEWS_LIMITS.video) {
      req.resume();
      return send(res, 413, { error: 'File too large' });
    }

    const name = path.basename(cleanText(url.searchParams.get('name'), 120)) || 'file';
    const id = crypto.randomUUID();
    const tmpPath = path.join(NEWS_DIR, id + '.part');
    const received = await receiveNewsMedia(req, tmpPath, { allowZip: true });
    const filename = id + received.ext;
    try {
      fs.renameSync(tmpPath, path.join(NEWS_DIR, filename));
    } catch (err) {
      log('ERROR', 'News file save failed: ' + err.message);
      try { fs.unlinkSync(tmpPath); } catch (_) {}
      return send(res, 500, { error: 'Could not save the file on the server computer' });
    }

    db.newsMedia[id] = {
      id,
      kind: received.kind,
      mimeType: received.mimeType,
      size: received.size,
      name,
      filename,
      uploadedBy: me.userId,
      ts: Date.now(),
      newsId: null
    };

    saveDbImmediately();
    log('NEWS', me.userId + ' uploaded ' + received.kind + ' (' + received.size + ' bytes)');
    return send(res, 201, { media: newsMediaView(id) });
  }

  const newsMediaGet = req.method === 'GET' &&
    url.pathname.match(/^\/news\/media\/([a-f0-9-]{36})$/);

  if (newsMediaGet) {
    const rec = Object.prototype.hasOwnProperty.call(db.newsMedia, newsMediaGet[1])
      ? db.newsMedia[newsMediaGet[1]] : null;
    if (!rec) return send(res, 404, { error: 'No such file' });

    return serveNewsMedia(req, res, rec);
  }

  if (route === 'POST /news') {
    if (!isAdmin(me)) return send(res, 403, { error: 'Admin access required' });

    const parsed = parseNewsBody(await readJson(req), null);
    if (parsed.error) return send(res, 400, { error: parsed.error });

    const item = {
      id: crypto.randomUUID(),
      title: parsed.title,
      html: parsed.html,
      media: parsed.mediaIds,
      authorId: me.userId,
      ts: Date.now(),
      editedAt: null
    };

    for (const id of item.media) db.newsMedia[id].newsId = item.id;
    db.news.push(item);
    saveDbImmediately();
    log('NEWS', me.userId + ' published announcement "' + item.title + '"');
    return send(res, 201, { news: newsView(item) });
  }

  const newsAction = req.method === 'POST' &&
    url.pathname.match(/^\/news\/([a-f0-9-]{36})\/(edit|delete)$/);

  if (newsAction) {
    if (!isAdmin(me)) return send(res, 403, { error: 'Admin access required' });

    const item = db.news.find((n) => n.id === newsAction[1]);
    if (!item) return send(res, 404, { error: 'No such announcement' });

    if (newsAction[2] === 'delete') {
      item.media.forEach(removeNewsMedia);
      db.news = db.news.filter((n) => n.id !== item.id);
      saveDbImmediately();
      log('NEWS', me.userId + ' deleted announcement "' + item.title + '"');
      return send(res, 200, { ok: true });
    }

    const parsed = parseNewsBody(await readJson(req), item.id);
    if (parsed.error) return send(res, 400, { error: parsed.error });

    for (const id of item.media) {
      if (!parsed.mediaIds.includes(id)) removeNewsMedia(id);
    }

    for (const id of parsed.mediaIds) db.newsMedia[id].newsId = item.id;
    item.title = parsed.title;
    item.html = parsed.html;
    item.media = parsed.mediaIds;
    item.editedAt = Date.now();
    saveDbImmediately();
    log('NEWS', me.userId + ' edited announcement "' + item.title + '"');
    return send(res, 200, { news: newsView(item) });
  }

  if (route === 'POST /posts') {
    const { caption, mimeType, imageData, mediaId } = await readJson(req);
    if (typeof caption !== 'string' || caption.length > MAX_CAPTION_LEN) {
      return send(res, 400, { error: 'Caption must be 1000 characters or fewer' });
    }

    let filename = null, savedMimeType = mimeType || null, attachedMedia = null, byteCount = 0;
    if (typeof mediaId === 'string' && db.socialMedia && db.socialMedia[mediaId]) {
      attachedMedia = db.socialMedia[mediaId];
      if (attachedMedia.scope !== 'post' || attachedMedia.uploadedBy !== me.userId ||
          attachedMedia.postId || attachedMedia.messageId) {
        return send(res, 400, { error: 'That attachment is not available for this post' });
      }
      filename = attachedMedia.filename;
      savedMimeType = attachedMedia.mimeType;
      byteCount = attachedMedia.size;
    } else {
      const img = social.readImage(mimeType, imageData);
      if (img.error) return send(res, 400, { error: img.error });
      filename = crypto.randomUUID() + img.type.extension;
      try {
        fs.writeFileSync(path.join(UPLOAD_DIR, filename), img.buffer, { flag: 'wx' });
      } catch (err) {
        log('ERROR', 'Image save failed: ' + err.message);
        return send(res, 500, { error: 'Could not save image on server computer' });
      }
      savedMimeType = mimeType;
      byteCount = img.buffer.length;
    }

    const id = crypto.randomUUID();
    const post = {
      id, userId: me.userId, caption: caption.trim(),
      filename: attachedMedia ? null : filename, mimeType: savedMimeType,
      mediaId: attachedMedia ? attachedMedia.id : null,
      mediaKind: attachedMedia ? attachedMedia.kind : null,
      likes: [], ts: Date.now()
    };
    if (attachedMedia) attachedMedia.postId = id;
    db.posts.push(post);
    saveDbImmediately();
    log('POST', `${me.userId} published ${attachedMedia ? attachedMedia.kind : 'image'} post ${id} (${byteCount} bytes)`);
    const token = getToken(req, url);
    return send(res, 201, {
      post: social.postView(post, token, me.userId, social.commentCounts())
    });
  }

  if (
    req.method === 'GET' &&
    url.pathname.startsWith('/uploads/')
  ) {
    let filename;
    try {
      filename = decodeURIComponent(
        url.pathname.slice('/uploads/'.length)
      );
    } catch {
      return send(res, 400, { error: 'Invalid image path' });
    }

    if (
      !filename ||
      path.basename(filename) !== filename ||
      !/^[a-f0-9-]+\.(jpg|png|gif|webp)$/.test(filename)
    ) {
      return send(res, 400, { error: 'Invalid image path' });
    }

    const post = db.posts.find((p) => p.filename === filename);
    if (!post) return send(res, 404, { error: 'Image not found' });

    const filePath = path.join(UPLOAD_DIR, filename);
    if (!fs.existsSync(filePath)) return send(res, 404, { error: 'Image file is missing' });

    const mime = {
      '.jpg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.webp': 'image/webp'
    }[path.extname(filename)];
    res.writeHead(200, {
      'Content-Type': mime,
      'Content-Length': fs.statSync(filePath).size,
      'Cache-Control': 'private, max-age=3600',
      'X-Content-Type-Options': 'nosniff'
    });

    return fs.createReadStream(filePath).pipe(res);
  }

  return send(res, 404, { error: 'Not found' });
}

const REPO_DIR = path.join(__dirname, 'repo');

function serveRepo(req, res, pathname) {
  if (pathname !== '/repo' && !pathname.startsWith('/repo/')) return false;

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, {
      'Allow': 'GET, HEAD',
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store'
    });
    res.end('Method not allowed');
    return true;
  }

  if (pathname === '/repo') {
    res.writeHead(301, { Location: '/repo/', 'Cache-Control': 'no-store' });
    res.end();
    return true;
  }

  let relativePath;
  try {
    relativePath = decodeURIComponent(pathname.slice('/repo/'.length));
  } catch {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Bad request');
    return true;
  }

  const segments = relativePath.split(/[\\/]+/);
  if (segments.some((segment) => segment.startsWith('.'))) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
    return true;
  }

  let filePath = path.resolve(REPO_DIR, relativePath || '.');
  const repoRoot = path.resolve(REPO_DIR);
  if (filePath !== repoRoot && !filePath.startsWith(repoRoot + path.sep)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Forbidden');
    return true;
  }

  try {
    if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
      if (!pathname.endsWith('/')) {
        res.writeHead(301, {
          Location: pathname + '/',
          'Cache-Control': 'no-store'
        });
        res.end();
        return true;
      }
      filePath = path.join(filePath, 'index.html');
    }

    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
      res.writeHead(404, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
      });
      res.end('Repository file not found');
      return true;
    }

    const ext = path.extname(filePath).toLowerCase();
    const mimeTypes = {
      '.html': 'text/html; charset=utf-8',
      '.htm': 'text/html; charset=utf-8',
      '.txt': 'text/plain; charset=utf-8',
      '.json': 'application/json; charset=utf-8',
      '.xml': 'application/xml; charset=utf-8',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.gif': 'image/gif',
      '.svg': 'image/svg+xml',
      '.deb': 'application/vnd.debian.binary-package',
      '.exe': 'application/vnd.microsoft.portable-executable',
      '.bz2': 'application/octet-stream',
      '.gz': 'application/octet-stream',
      '.xz': 'application/octet-stream',
      '.zst': 'application/octet-stream'
    };

    const stat = fs.statSync(filePath);
    res.writeHead(200, {
      'Content-Type': mimeTypes[ext] || 'application/octet-stream',
      'Content-Length': stat.size,
      'Cache-Control': (path.basename(filePath) === 'Packages' ||
                        path.basename(filePath) === 'Packages.bz2' ||
                        path.basename(filePath) === 'Release')
        ? 'no-cache'
        : 'public, max-age=300',
      'X-Content-Type-Options': 'nosniff'
    });

    if (req.method === 'HEAD') {
      res.end();
    } else {
      fs.createReadStream(filePath)
        .on('error', (err) => {
          log('ERROR', `Repo file read failed (${filePath}): ${err.message}`);
          if (!res.headersSent) res.writeHead(500);
          res.end();
        })
        .pipe(res);
    }
    return true;
  } catch (err) {
    log('ERROR', `Repo request failed (${pathname}): ${err.message}`);
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
    }
    res.end('Repository server error');
    return true;
  }
}

const server = http.createServer((req, res) => {
  let requestUrl;
  try {
    requestUrl = new URL(req.url || '/', 'http://localhost');
  } catch {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Bad request');
  }

  if (serveRepo(req, res, requestUrl.pathname)) return;

  const uiPath = requestUrl.pathname;

  if (req.method === 'GET' && (uiPath === '/' || uiPath === '/index.html')) {
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache'
    });

    return res.end(UI_HTML);
  }

  handle(req, res).catch((err) => {
    log('ERROR', `${req.method} ${req.url}: ${err.message}`);
    if (!res.headersSent) {
      send(res, 400, { error: err.message || 'Request failed' });
    } else {
      res.end();
    }
  });
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    log('ERROR', `Port ${PORT} is already in use. Is the server running, or is another web server (nginx/Apache) on it?`);
  } else if (err.code === 'EACCES') {
    log('ERROR', `Not allowed to use port ${PORT}. Ports below 1024 need root (sudo node server.js) ` +
      `or: sudo setcap 'cap_net_bind_service=+ep' $(which node)`);
  } else {
    log('ERROR', err.message);
  }

  process.exit(1);
});

server.requestTimeout = 0;

const skyglowSecureContext = tls.createSecureContext({ key: SKYGLOW_TLS_KEY, cert: SKYGLOW_TLS_CERT, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3' });
function routeTlsSocket(rawSocket) {
  const socket = new tls.TLSSocket(rawSocket, { isServer: true, secureContext: skyglowSecureContext });
  socket.on('secure', () => {
    socket.setNoDelay(true);
    sgnHandleSocket(socket);
  });
  socket.on('error', e => { if (e && e.code !== 'ECONNRESET') log('SKYGLOW', 'TLS handshake rejected: ' + e.message); });
  socket.resume();
}

const sharedPortMux = net.createServer((socket) => {
  socket.setNoDelay(true);
  let first = true;
  const sniff = (chunk) => {
    if (!first) return;
    first = false;
    socket.pause();
    socket.removeListener('data', sniff);
    if (chunk.length >= 1 && chunk[0] === 0x16) {
      socket.unshift(chunk);
      routeTlsSocket(socket);
    } else {
      socket.unshift(chunk);
      server.emit('connection', socket);
    }
    if (!(chunk.length >= 1 && chunk[0] === 0x16)) socket.resume();
  };
  socket.on('data', sniff);
  socket.on('error', () => {});
});
sharedPortMux.on('error', (err) => {
  if (err.code === 'EADDRINUSE') log('ERROR', `Port ${PORT} is already in use. Stop the old server before replacing server.js.`);
  else if (err.code === 'EACCES') log('ERROR', `Not allowed to use port ${PORT}; on Windows, run the terminal as Administrator if required.`);
  else log('ERROR', err.message);
  process.exit(1);
});

sharedPortMux.listen(PORT, HOST, () => {
  log('INFO', `iLegacy WebUI/API + native Skyglow TLS multiplexer running on port ${PORT}`);
  log('INFO', `Open http://localhost:${PORT} in your browser`);
  log('INFO', `Health check: http://localhost:${PORT}/health`);
  log('INFO', `Skyglow TCP/TLS protocol is multiplexed on this same port; public port 1444 may forward here`);
  log('INFO', `Skyglow certificate: GET http://localhost:${PORT}/sgn/snd/server_cert.pem`);
  log('INFO', `Cydia repository files: ${REPO_DIR} -> http://localhost:${PORT}/repo/`);
});

const UI_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>iLegacy</title>
<style>
*{box-sizing:border-box}
body{
  margin:0;
  font-family:system-ui,"Segoe UI",sans-serif;
  background:#f0f2f5;
  color:#1c1e21;
  min-height:100vh
}
button{
  cursor:pointer;
  border:0;
  border-radius:8px;
  padding:10px 14px;
  background:#2563eb;
  color:#fff;
  font-size:14px
}
button:disabled{opacity:.55;cursor:wait}
button.grey{background:#e4e6eb;color:#1c1e21}
button.danger{background:#dc2626}
button.linklike{
  background:none;
  color:inherit;
  padding:0;
  font:inherit;
  font-weight:600;
  text-align:left;
  border-radius:0
}
button.linklike:hover{text-decoration:underline}
input{
  width:100%;
  padding:10px;
  border:1px solid #ccd0d5;
  border-radius:8px;
  font-size:14px
}
input[type=color]{padding:2px;height:40px;width:70px}
textarea{font:inherit}
#auth{
  max-width:340px;
  margin:10vh auto;
  background:#fff;
  padding:24px;
  border-radius:12px;
  box-shadow:0 2px 10px rgba(0,0,0,.1)
}
#auth h1{margin:0 0 4px}
#auth p{color:#65676b;margin:0 0 16px}
#auth input{margin-bottom:10px}
.row{display:flex;gap:8px}
#err{color:#c0392b;min-height:20px;font-size:14px;margin-top:8px}
#app{display:none;height:100vh;height:100dvh;min-height:0;flex-direction:column;overflow:hidden;background:#f3f5f9}
#topbar{
  display:flex;align-items:center;justify-content:space-between;gap:18px;
  flex:0 0 auto;min-height:68px;padding:10px 18px;background:#fff;
  border-bottom:1px solid #cfd6e2;box-shadow:0 2px 8px rgba(20,35,65,.05);z-index:20
}
#accountbar{display:flex;align-items:center;gap:14px;min-width:0}
#accountdetails{min-width:0;line-height:1.35}
#accountdetails .accountname{font-weight:700;overflow-wrap:anywhere}
#accountdetails .accountid{font-size:12px;color:#65718a;white-space:nowrap}
#myid{font-family:monospace;background:#eef2ff;padding:2px 6px;border-radius:6px;color:#263d7a}
#logoutbtn{flex-shrink:0;border:1px solid #d7deea;background:#f7f8fb;color:#263248;padding:8px 12px}
#nav{display:flex;align-items:center;justify-content:flex-end;gap:6px;min-width:0}
#nav button{flex:0 0 auto;white-space:nowrap;padding:10px 12px;border:1px solid transparent;border-radius:8px}
#nav button:not(.grey){box-shadow:0 2px 5px rgba(37,99,235,.15)}
#nav button.grey{background:transparent;color:#4b5870}
#nav button.grey:hover{background:#eef2f8;color:#1d355d}
#mobilemenubtn{display:none;flex-shrink:0;padding:9px 12px}
#side{
  width:290px;flex:0 0 290px;background:#fff;border-right:1px solid #d8deea;
  display:flex;flex-direction:column;min-height:0;min-width:0
}
.top{padding:12px;border-bottom:1px solid #e7ebf2}
#chattools{display:none;flex-direction:column;flex:1;min-height:0}
#convos{flex:1;min-height:0;overflow-y:auto;overscroll-behavior:contain}
.convo{
  padding:12px 14px;
  border-bottom:1px solid #f0f0f0;
  cursor:pointer
}
.convo:hover,.convo.active{background:#eef2ff}
.convo b{display:block}
.convo small{
  color:#65676b;
  display:block;
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis
}
#workspace{
  flex:1;
  min-width:0;
  min-height:0;
  display:flex;
  flex-direction:column
}
#chatview{
  flex:1;
  min-height:0;
  display:flex;
  flex-direction:column
}
#main{
  flex:1;
  min-height:0;
  min-width:0;
  display:flex;
  flex-direction:column
}
#head{
  padding:14px;
  background:#fff;
  border-bottom:1px solid #ddd;
  font-weight:600
}
#msgs{
  flex:1;
  overflow-y:auto;
  padding:16px;
  display:flex;
  flex-direction:column;
  gap:6px
}
.msg{
  max-width:70%;
  padding:8px 12px;
  border-radius:14px;
  overflow-wrap:anywhere;
  white-space:pre-wrap
}
.msg.mine{align-self:flex-end;background:#2563eb;color:#fff}
.msg.theirs{align-self:flex-start;background:#fff}
.msg small{display:block;opacity:.72;font-size:11px;margin-top:3px}
.msg img.dmimg{display:block;max-width:min(360px,100%);max-height:360px;object-fit:contain;border-radius:9px;margin:2px 0 6px;cursor:pointer}
.msgstatus{display:block;text-align:right;font-size:10px;opacity:.8;margin-top:3px}
.msgstatus.read{color:#bfdbfe}
#dmimage{width:190px;min-width:120px;padding:6px;border:0;background:#f0f2f5}
.msg .socialmedia{display:block;max-width:min(420px,100%);max-height:420px;margin:2px 0 6px;border-radius:9px;background:#111}
.feedpost .socialmedia{display:block;width:100%;max-height:650px;background:#111;object-fit:contain}
.feedpost video.socialmedia,.msg video.socialmedia{height:auto}
.feedpost audio.socialmedia,.msg audio.socialmedia{width:100%;max-width:480px;background:transparent}
#compose{
  display:flex;
  gap:8px;
  padding:12px;
  background:#fff;
  border-top:1px solid #ddd
}
.empty{margin:auto;color:#65676b;text-align:center;padding:20px}
#feed{
  display:none;
  flex:1;
  min-height:0;
  overflow-y:auto;
  padding:20px
}
.feedinner{max-width:760px;width:100%;margin:0 auto}
.postbox,.feedpost{
  background:#fff;
  border:1px solid #ddd;
  border-radius:12px;
  margin-bottom:16px
}
.postbox{padding:16px}
.postbox h2{margin:0 0 12px;font-size:20px}
#imagefile{display:block;margin:10px 0;max-width:100%}
#caption{
  display:block;
  width:100%;
  min-height:75px;
  resize:vertical;
  padding:10px;
  border:1px solid #ccd0d5;
  border-radius:8px;
  margin:10px 0
}
#feedstatus{
  font-size:13px;
  color:#65676b;
  min-height:20px;
  margin-top:8px
}
.feedpost{overflow:hidden}
.feedposthead{
  padding:12px 14px;
  display:flex;
  gap:10px;
  align-items:center;
  overflow-wrap:anywhere
}
.feedposthead small{
  display:block;
  color:#65676b;
  font-weight:400;
  margin-top:2px
}
.feedpost img.postimg{
  display:block;
  width:100%;
  max-height:650px;
  object-fit:contain;
  background:#f7f7f7
}
.feedcaption{
  padding:12px 14px;
  white-space:pre-wrap;
  overflow-wrap:anywhere
}
.avatar{
  border-radius:50%;
  object-fit:cover;
  flex-shrink:0;
  background:#dbe4ff
}
.avatar-ph{
  display:flex;
  align-items:center;
  justify-content:center;
  font-weight:700;
  color:#2563eb;
  background:#dbe4ff
}
.actions{
  display:flex;
  gap:8px;
  padding:6px 14px 12px
}
button.act{
  background:#f0f2f5;
  color:#1c1e21;
  padding:6px 12px
}
button.act.on{background:#fee2e2;color:#dc2626}
.comments{
  border-top:1px solid #eee;
  padding:10px 14px;
  background:#fafafa
}
.comment{
  display:flex;
  gap:8px;
  margin-bottom:10px;
  align-items:flex-start
}
.comment .cbody{flex:1;min-width:0;overflow-wrap:anywhere}
.comment .ctext{white-space:pre-wrap}
.comment small{color:#65676b}
.comment button.x{
  background:none;
  color:#65676b;
  padding:2px 6px;
  font-size:12px
}
.cform{display:flex;gap:8px}

#profilepage{
  display:none;
  flex:1;
  min-height:0
}
#profilecol{
  flex:1;
  min-width:0;
  overflow-y:auto;
  padding:20px;
  background:#f0f2f5
}
#inbox{
  width:340px;
  flex-shrink:0;
  background:#fff;
  border-left:1px solid #ddd;
  overflow-y:auto;
  display:flex;
  flex-direction:column
}
#inboxhead{
  padding:14px;
  border-bottom:1px solid #eee;
  display:flex;
  justify-content:space-between;
  align-items:center;
  font-weight:700;
  font-size:17px
}
#inboxhead button{padding:6px 10px;font-size:12px}
.notif{
  display:flex;
  gap:10px;
  padding:12px 14px;
  border-bottom:1px solid #f0f0f0;
  align-items:center
}
.notif.unread{background:#eef2ff}
.notif .ntext{flex:1;min-width:0;overflow-wrap:anywhere;font-size:14px}
.notif .ntext small{display:block;color:#65676b;margin-top:2px}
.notif img.thumb{
  width:42px;
  height:42px;
  object-fit:cover;
  border-radius:6px;
  flex-shrink:0
}
.profilecard{
  background:#fff;
  border:1px solid #ddd;
  border-radius:12px;
  padding:20px;
  margin-bottom:16px
}
.profiletop{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.profiletop h2{margin:0}
.muted{color:#65676b;font-size:14px}
.bio{white-space:pre-wrap;overflow-wrap:anywhere;margin:14px 0}
.stats{display:flex;gap:18px;font-size:14px;margin:10px 0}
.profbtns{display:flex;gap:8px;flex-wrap:wrap}
.editbox{
  margin-top:16px;
  padding-top:16px;
  border-top:1px solid #eee
}
.editbox label{display:block;font-size:13px;color:#65676b;margin:10px 0 4px}
.editbox textarea{
  width:100%;
  min-height:80px;
  padding:10px;
  border:1px solid #ccd0d5;
  border-radius:8px;
  resize:vertical
}
.editstatus{font-size:13px;color:#65676b;min-height:20px;margin-top:8px}

#drivepage{
  display:none;
  flex:1;
  min-height:0;
  flex-direction:column;
  overflow-y:auto;
  padding:20px;
  background:#f0f2f5
}
#downloadspage{
  display:none;
  flex:1;
  min-height:0;
  flex-direction:column;
  overflow-y:auto;
  padding:20px;
  background:#f0f2f5
}
.dlbar{
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:8px;
  margin-bottom:16px
}
.dlbar h2{margin:0}
.dlcat{
  background:#fff;
  border:1px solid #ddd;
  border-radius:12px;
  margin-bottom:16px;
  overflow:hidden
}
.dlcathead{
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:8px;
  padding:12px 14px;
  border-bottom:1px solid #eee;
  font-weight:700;
  font-size:17px;
  overflow-wrap:anywhere
}
.dlcathead small{color:#65676b;font-weight:400;font-size:13px;margin-left:6px}
.dlrow{display:flex;gap:12px;overflow-x:auto;padding:14px}
.dlcard{
  flex:0 0 240px;
  display:flex;
  flex-direction:column;
  gap:4px;
  padding:12px;
  background:#fafafa;
  border:1px solid #e4e6eb;
  border-radius:10px;
  font-size:14px;
  overflow-wrap:anywhere
}
.dlcard .dltitle{font-weight:700;font-size:15px}
.dlcard .dlver{
  display:inline-block;
  background:#eef2ff;
  color:#2563eb;
  border-radius:6px;
  padding:1px 7px;
  font-size:12px;
  font-weight:600;
  margin-left:4px
}
.dlcard .dlnew{
  display:inline-block;
  background:#dcfce7;
  color:#15803d;
  border-radius:6px;
  padding:1px 7px;
  font-size:11px;
  font-weight:700;
  margin-left:4px
}
.dltag{
  display:inline-block;
  border-radius:6px;
  padding:1px 7px;
  font-size:11px;
  font-weight:700;
  margin-left:4px;
  background:#e4e6eb;
  color:#1c1e21
}
.dltag.tag-major-update{background:#ede9fe;color:#6d28d9}
.dltag.tag-bug-fix{background:#dbeafe;color:#1d4ed8}
.dltag.tag-untested{background:#fee2e2;color:#b91c1c}
.dltag.tag-beta{background:#fef3c7;color:#b45309}
.dltag.tag-security-fix{background:#ffedd5;color:#c2410c}
.histsec{margin-top:16px}
.histsec h4{margin:0 0 6px;font-size:15px}
.histscroll{max-height:240px;overflow:auto;border:1px solid #e4e6eb;border-radius:8px}
table.hist{width:100%;border-collapse:collapse;font-size:13px}
table.hist th{
  position:sticky;
  top:0;
  background:#f0f2f5;
  text-align:left;
  padding:6px 8px;
  font-size:12px
}
table.hist td{padding:6px 8px;border-top:1px solid #f0f0f0;overflow-wrap:anywhere;vertical-align:top}
.histempty{padding:10px;color:#65676b;font-size:13px}
.dlcard small{color:#65676b}
.dlcard .dldesc{white-space:pre-wrap;margin:4px 0}
.dlcard .dlbtns{display:flex;gap:6px;margin-top:auto;padding-top:8px}
a.btnlink{
  display:inline-block;
  border-radius:8px;
  padding:8px 12px;
  background:#2563eb;
  color:#fff;
  font-size:14px;
  text-decoration:none
}
.modalbg{
  display:none;
  position:fixed;
  top:0;left:0;right:0;bottom:0;
  background:rgba(0,0,0,.5);
  align-items:center;
  justify-content:center;
  z-index:50;
  padding:12px
}
.modal{
  background:#fff;
  border-radius:12px;
  padding:20px;
  width:100%;
  max-width:440px;
  max-height:92vh;
  overflow-y:auto
}
.modal h3{margin:0 0 6px}
.modal label{display:block;font-size:13px;color:#65676b;margin:10px 0 4px}
.modal select,.modal textarea{
  width:100%;
  padding:10px;
  border:1px solid #ccd0d5;
  border-radius:8px;
  font-size:14px
}
.modal textarea{min-height:70px;resize:vertical}
.modal .row{margin-top:16px;justify-content:flex-end}
.modalstatus{font-size:13px;color:#c0392b;min-height:20px;margin-top:8px}

#newspage{
  display:none;
  flex:1;
  min-height:0;
  flex-direction:column;
  overflow-y:auto;
  padding:20px;
  background:#f0f2f5
}
.newscard{
  background:#fff;
  border:1px solid #ddd;
  border-radius:12px;
  margin:0 auto 16px;
  max-width:760px;
  width:100%;
  overflow:hidden
}
.newshead{padding:14px 16px 4px}
.newshead h3{margin:0 0 4px;font-size:22px;overflow-wrap:anywhere}
.newshead small{color:#65676b}
.newsbody{
  padding:8px 16px 12px;
  overflow-wrap:anywhere;
  line-height:1.45;
  font-size:16px
}
.newsbody p,.newsbody div{margin:0 0 6px}
.newsbody ul,.newsbody ol{margin:6px 0 6px 22px;padding:0}
.newsbody blockquote{margin:8px 0;padding-left:12px;border-left:3px solid #ccd0d5}
.newsmedia{padding:0 16px 12px;display:flex;flex-direction:column;gap:12px}
.newsmedia img{
  display:block;
  max-width:100%;
  max-height:600px;
  border-radius:8px;
  cursor:pointer;
  margin:0 auto
}
.newsmedia video{display:block;width:100%;max-height:480px;background:#000;border-radius:8px}
.newsmedia audio{display:block;width:100%}
.newsmedia .mname{display:block;color:#65676b;font-size:12px;margin-bottom:4px}
.newsfoot{display:flex;gap:8px;padding:0 16px 14px}
.modal.wide{max-width:760px}
.newstools{
  display:flex;
  flex-wrap:wrap;
  gap:6px;
  align-items:center;
  padding:8px;
  background:#f0f2f5;
  border:1px solid #ccd0d5;
  border-bottom:0;
  border-radius:8px 8px 0 0
}
.newstools select{width:auto;padding:6px;font-size:13px}
.newstools button{padding:6px 10px;font-size:13px;background:#fff;color:#1c1e21;border:1px solid #ccd0d5}
.newstools label{display:flex;align-items:center;gap:4px;margin:0;font-size:13px;color:#1c1e21}
.newstools input[type=color]{width:34px;height:30px;padding:1px}
#neditor{
  min-height:180px;
  max-height:38vh;
  overflow-y:auto;
  padding:10px;
  border:1px solid #ccd0d5;
  border-radius:0 0 8px 8px;
  font-size:16px;
  line-height:1.4;
  overflow-wrap:anywhere;
  outline:0
}
#neditor:focus{border-color:#2563eb}
.attach{
  display:flex;
  gap:8px;
  align-items:center;
  padding:6px 0;
  border-bottom:1px solid #eee;
  font-size:13px
}
.attach .aname{flex:1;min-width:0;overflow-wrap:anywhere}
.attach .akind{
  background:#eef2ff;
  color:#2563eb;
  border-radius:6px;
  padding:1px 6px;
  font-size:11px;
  font-weight:700
}
.attach button{padding:3px 8px;font-size:12px}

.ring{border:4px solid #fff;box-shadow:0 0 0 1px #c9cdd3}
.ring.ring-on{border-color:#22c55e;box-shadow:0 0 0 1px #16a34a}
.presence{font-size:13px;font-weight:700;margin-top:2px;color:#65676b}
.presence.on{color:#16a34a}
a.filelink{
  display:inline-block;
  padding:8px 12px;
  border-radius:8px;
  background:#eef2ff;
  color:#2563eb;
  text-decoration:none;
  font-size:14px;
  overflow-wrap:anywhere
}
.msg.mine a.filelink{background:#1d4ed8;color:#fff}

@media(max-width:900px){
  #topbar{gap:10px;padding:9px 12px;min-height:60px;flex-wrap:wrap}
  #accountbar{flex:1;gap:9px}
  #accountdetails .accountid{font-size:11px}
  #mobilemenubtn{display:inline-flex;align-items:center;gap:7px}
  #nav{display:none;order:3;flex:0 0 100%;width:100%;padding:10px 0 2px;border-top:1px solid #e7ebf2;flex-wrap:wrap;justify-content:flex-start;gap:7px}
  #topbar.menu-open #nav{display:flex}
  #nav button{flex:1 1 calc(50% - 7px);white-space:normal;text-align:center}
  #side{width:100%;flex:0 0 auto;max-height:34%;min-height:120px;border-right:0;border-bottom:1px solid #d8deea}
  #chattools{min-height:0}
  #chattools>.top{padding:8px 10px}
  #convos{min-height:0;max-height:none}
  #workspace{flex:1 1 0;min-height:0;overflow:hidden}
  #chatview{min-height:0;overflow:hidden}
  #main{min-height:0;overflow:hidden}
  #head{padding:10px;font-size:14px}
  #msgs{padding:10px;overscroll-behavior:contain}
  #compose{padding:8px;gap:6px;align-items:center}
  #compose #dmimage{width:54px;min-width:54px;max-width:54px;font-size:0}
  #compose #text{min-width:0;flex:1}
  #compose #sendbtn{flex:0 0 auto;padding:10px}
  #feed{padding:10px}
  .msg{max-width:88%}
  #profilepage{flex-direction:column;overflow-y:auto}
  #profilecol{flex:none;overflow:visible;padding:10px}
  #inbox{width:100%;min-height:220px;border-left:0;border-top:1px solid #ddd;overflow:visible}
  #downloadspage{padding:10px}
  #drivepage{padding:10px}
  #newspage{padding:10px}
}
@media(min-width:901px){
  #app{flex-direction:column}
  #side{height:100%;max-height:none}
  #app>#side,#app>#workspace{min-height:0}
  #app{position:relative}
  #side{position:absolute;top:68px;bottom:0;left:0;display:none}
  #workspace{position:absolute;top:68px;right:0;bottom:0;left:0}
}
@media(max-width:420px){
  #accountdetails .accountname{font-size:13px}
  #logoutbtn{padding:7px 9px;font-size:12px}
  #side{max-height:36%}
  #compose #dmimage{width:42px;min-width:42px;max-width:42px}
}

body.dark-mode{background:#242424!important;color:#f2f2f2!important;color-scheme:dark}
body.dark-mode #app,
body.dark-mode #auth,
body.dark-mode #topbar,
body.dark-mode #side,
body.dark-mode #workspace,
body.dark-mode #head,
body.dark-mode #compose,
body.dark-mode #feed,
body.dark-mode #msgs,
body.dark-mode #profilepage,
body.dark-mode #profilecol,
body.dark-mode #inbox,
body.dark-mode #inboxhead,
body.dark-mode #downloadspage,
body.dark-mode #drivepage,
body.dark-mode #newspage,
body.dark-mode .profilecard,
body.dark-mode .editbox,
body.dark-mode .card,
body.dark-mode .panel,
body.dark-mode .modal,
body.dark-mode .dialog,
body.dark-mode .conversation,
body.dark-mode .chatitem,
body.dark-mode .convo,
body.dark-mode .post,
body.dark-mode .postbox,
body.dark-mode .feedpost,
body.dark-mode .inboxitem,
body.dark-mode .notif,
body.dark-mode .empty,
body.dark-mode .histempty,
body.dark-mode .dlcat,
body.dark-mode .dlcard,
body.dark-mode #callpanel,
body.dark-mode #drivemyquota,
body.dark-mode #drivegrant,
body.dark-mode [style*="background:#fff"],
body.dark-mode [style*="background: #fff"],
body.dark-mode [style*="background-color: rgb(255, 255, 255)"]{background-color:#303030!important;color:#f2f2f2!important}
body.dark-mode *{border-color:#505050}
body.dark-mode h1,body.dark-mode h2,body.dark-mode h3,
body.dark-mode p,body.dark-mode label,body.dark-mode span,
body.dark-mode small,body.dark-mode strong,body.dark-mode b,
body.dark-mode li,body.dark-mode td,body.dark-mode th,
body.dark-mode .muted,body.dark-mode .accountname,
body.dark-mode .accountid,body.dark-mode .presence,
body.dark-mode .bio,body.dark-mode .stats{color:#f2f2f2}
body.dark-mode input:not([type="checkbox"]):not([type="color"]),
body.dark-mode textarea,body.dark-mode select{background:#252525!important;color:#f2f2f2!important;border-color:#555!important}
body.dark-mode input::placeholder,body.dark-mode textarea::placeholder{color:#bdbdbd!important}
body.dark-mode button.grey{background:#383838!important;color:#f2f2f2!important;border:1px solid #555!important}
body.dark-mode #myid{background:#444!important;color:#fff!important}
body.dark-mode #nav button,body.dark-mode button:not(.grey){color:#fff}
body.dark-mode .msg{color:#111!important}
body.dark-mode .msg *{color:#111!important}
body.dark-mode .msg.mine{background:#9bbcff!important}
body.dark-mode .msg.theirs{background:#e7e7e7!important}
body.dark-mode .msgstatus.read{color:#333!important}
body.dark-mode .msg .socialmedia,body.dark-mode .feedpost .socialmedia{background:#111!important}
body.dark-mode #drivefiles > div:not(.empty){background:#303030!important;color:#f2f2f2!important}
body.dark-mode #drivefiles > div:not(.empty) b,
body.dark-mode #drivefiles > div:not(.empty) .muted{color:#f2f2f2!important}
body.dark-mode #drivefiles > div.empty{background:#303030!important;color:#f2f2f2!important}

body.dark-mode #newspage { background:#303030 !important; color:#f2f2f2 !important; }
body.dark-mode .newscard,
body.dark-mode .newscard *:not(button):not(input):not(textarea):not(a),
body.dark-mode .feedpost,
body.dark-mode .feedpost *:not(button):not(input):not(textarea):not(a),
body.dark-mode .postbox,
body.dark-mode .postbox *:not(button):not(input):not(textarea):not(a) {
  background-color:#303030 !important;
  color:#f2f2f2 !important;
}
body.dark-mode .newscard a,
body.dark-mode .feedpost a,
body.dark-mode .postbox a { color:#8ab4ff !important; }
body.dark-mode .newshead small,
body.dark-mode .feedposthead small,
body.dark-mode .newscard small { color:#c8c8c8 !important; }
body.dark-mode .feedpost img.postimg { background:#242424 !important; }
body.dark-mode #drivefiles > div:not(.empty),
body.dark-mode #drivefiles > div:not(.empty) *:not(button):not(a) {
  background-color:#303030 !important;
  color:#f2f2f2 !important;
}
body.dark-mode #dllist .dlcat { background:#303030 !important; color:#f2f2f2 !important; }
body.dark-mode #dllist .dlcathead,
body.dark-mode #dllist .dlrow,
body.dark-mode #dllist .dlcard { background:#303030 !important; color:#f2f2f2 !important; }
body.dark-mode #dllist .dlcathead *,
body.dark-mode #dllist .dlcard *:not(button):not(a) { color:#f2f2f2 !important; }

body.dark-mode #downloadspage,
body.dark-mode #dllist,
body.dark-mode #dllist .empty,
body.dark-mode #dllist .dlcat,
body.dark-mode #dllist .dlcathead,
body.dark-mode #dllist .dlrow,
body.dark-mode #dllist .dlcard,
body.dark-mode #dllist .histsec,
body.dark-mode #dllist .histscroll,
body.dark-mode #dllist table.hist,
body.dark-mode #dllist table.hist th,
body.dark-mode #dllist table.hist td {
  background-color:#202020 !important;
  color:#f7f7f7 !important;
}
body.dark-mode #dllist .dlcard {
  background-color:#252525 !important;
  border-color:#3b3b3b !important;
}
body.dark-mode #dllist .dlcat {
  border-color:#3b3b3b !important;
}
body.dark-mode #dllist .dlcathead,
body.dark-mode #dllist table.hist th,
body.dark-mode #dllist table.hist td {
  border-color:#3b3b3b !important;
}
body.dark-mode #dllist .dlcard :not(.dlver):not(.dlnew):not(.dltag):not(button):not(a),
body.dark-mode #dllist .dlcathead,
body.dark-mode #dllist .dlcathead small,
body.dark-mode #dllist .dlcard small,
body.dark-mode #dllist .dlcard .dldesc,
body.dark-mode #dllist .histsec h4,
body.dark-mode #dllist table.hist th,
body.dark-mode #dllist table.hist td,
body.dark-mode #dllist .empty {
  color:#f7f7f7 !important;
}
body.dark-mode #dllist .dlver { background:#263b65 !important; color:#e1eaff !important; }
body.dark-mode #dllist .dlnew { background:#17452d !important; color:#c7f9d9 !important; }
body.dark-mode #dllist .dltag { background:#383838 !important; color:#f7f7f7 !important; }
body.dark-mode #dllist .dltag.tag-major-update { background:#392c59 !important; color:#eee5ff !important; }
body.dark-mode #dllist .dltag.tag-bug-fix { background:#203b5e !important; color:#dceaff !important; }
body.dark-mode #dllist .dltag.tag-untested { background:#542727 !important; color:#ffe2e2 !important; }
body.dark-mode #dllist .dltag.tag-beta { background:#51421c !important; color:#fff0bd !important; }
body.dark-mode #dllist .dltag.tag-security-fix { background:#53321d !important; color:#ffe4ce !important; }
body.dark-mode #dllist button:not(.grey),
body.dark-mode #dllist a.btnlink { color:#fff !important; }
body.dark-mode #dllist button.act,
body.dark-mode #dllist button.grey {
  background-color:#3a3a3a !important;
  color:#f2f2f2 !important;
  border:1px solid #505050 !important;
  box-shadow:none !important;
}
body.dark-mode #dllist button.act:hover,
body.dark-mode #dllist button.grey:hover:not(:disabled) {
  background-color:#484848 !important;
  color:#ffffff !important;
}
body.dark-mode #dllist button.act:disabled,
body.dark-mode #dllist button.grey:disabled {
  background-color:#303030 !important;
  color:#bdbdbd !important;
  border-color:#404040 !important;
  opacity:1 !important;
}

#dllist .dlbtns {
  display:flex;
  flex-wrap:nowrap;
  align-items:center;
  gap:8px;
}
#dllist .dlbtns a.btnlink,
#dllist .dlbtns button {
  display:inline-flex;
  align-items:center;
  justify-content:center;
  flex:0 0 auto;
  white-space:nowrap;
  word-break:normal;
  overflow-wrap:normal;
  line-height:1.25;
  min-height:36px;
  box-sizing:border-box;
  padding:8px 12px;
}
#dllist .dlbtns a.btnlink { min-width:86px; }
#dllist .dlbtns button.act { min-width:48px; }
@media (max-width:520px) {
  #dllist .dlbtns { gap:6px; }
  #dllist .dlbtns a.btnlink,
  #dllist .dlbtns button { padding:8px 10px; }
}
</style>
</head>
<body>

<div id="auth">
  <h1>iLegacy</h1>
  <p>Sign in or create an account</p>
  <input id="u" placeholder="Username or User ID (IL-12345678)"
         autocomplete="username">
  <input id="p" type="password" placeholder="Password (8+ characters)"
         autocomplete="current-password">
  <div class="row">
    <button onclick="doAuth('login')">Log in</button>
    <button class="grey" onclick="doAuth('register')">Create account</button>
  </div>
  <div id="err"></div>
</div>

<div id="app">
  <header id="topbar">
    <div id="accountbar">
      <div id="accountdetails">
        <div class="accountname">Signed in as <b id="myname"></b></div>
        <div class="accountid">User ID: <span id="myid"></span></div>
      </div>
      <button id="logoutbtn" onclick="logout()">Sign out</button>
    </div>
    <button id="mobilemenubtn" type="button" aria-expanded="false" aria-controls="nav" onclick="toggleMobileNav()"><span aria-hidden="true">☰</span> Menu</button>
    <nav id="nav" aria-label="Main navigation">
      <button id="homeTab" onclick="showPage('home')">Home</button>
      <button id="messagesTab" class="grey"
              onclick="showPage('messages')">Messages</button>
      <button id="profileTab" class="grey"
              onclick="openProfile(null)">Profile</button>
      <button id="downloadsTab" class="grey"
              onclick="showPage('downloads')">Downloads</button>
      <button id="newsTab" class="grey wide"
              onclick="showPage('news')">iLegacy News</button>
      <button id="driveTab" class="grey wide"
              onclick="showPage('drive')">iLegacy Drive</button>
    </nav>
  </header>

  <div id="side">
    <div id="chattools">
      <div class="top">
        <div class="row">
          <input id="newid" placeholder="Chat with User ID">
          <button onclick="newChat()">Go</button>
        </div>
        <div id="err2" style="color:#c0392b;font-size:13px;margin-top:6px"></div>
      </div>
      <div id="convos"></div>
    </div>
  </div>

  <div id="workspace">
    <div id="feed">
      <div class="feedinner">
        <div class="postbox">
          <h2>Share media</h2>
          <form id="postform">
            <input id="imagefile" type="file"
                   accept="image/jpeg,image/png,image/gif,image/webp,audio/mpeg,video/mp4,.mp3,.mp4" required>
            <div class="muted">Photos/GIFs and MP3 up to 5 MB, MP4 video up to 7.5 GB</div>
            <textarea id="caption" maxlength="1000"
                      placeholder="Write a caption (optional)..."></textarea>
            <button id="publishbtn" type="submit">Publish post</button>
            <div id="feedstatus" aria-live="polite"></div>
          </form>
        </div>
        <div id="posts"><div class="empty">Loading feed...</div></div>
      </div>
    </div>

    <div id="chatview">
      <div id="main">
        <div id="head" style="display:flex;align-items:center;justify-content:space-between;gap:12px"><span id="chatheadtext">Pick a conversation or enter a User ID</span><button id="callbtn" type="button" class="grey" onclick="startVoiceCall()" disabled style="display:none;white-space:nowrap">☎ Call</button></div>
        <div id="msgs"><div class="empty">No conversation open</div></div>
        <div id="compose">
          <input id="dmimage" type="file" accept="image/jpeg,image/png,image/gif,image/webp,audio/mpeg,video/mp4,application/zip,application/x-zip-compressed,.mp3,.mp4,.zip" title="Attach photo, GIF, MP3, MP4, or ZIP" aria-label="Attach photo, GIF, MP3, MP4, or ZIP" disabled>
          <input id="text" placeholder="Type a message..." disabled>
          <button id="sendbtn" onclick="sendMsg()" disabled>Send</button>
        </div>
      </div>
    </div>

    <div id="callpanel" role="dialog" aria-live="polite" aria-label="iLegacy voice call" style="display:none;position:fixed;right:20px;bottom:20px;z-index:10000;background:#fff;border:1px solid #bbb;border-radius:14px;box-shadow:0 8px 32px #0003;padding:18px;min-width:260px;max-width:calc(100vw - 40px)">
      <div id="calltitle" style="font-weight:700;font-size:16px;margin-bottom:8px">iLegacy Calling</div>
      <div id="callstatus" class="muted" style="margin-bottom:14px">Ready</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button id="answercallbtn" type="button" onclick="answerVoiceCall()" style="display:none;background:#16a34a">Answer</button>
        <button id="declinecallbtn" type="button" class="grey" onclick="declineVoiceCall()" style="display:none">Decline</button>
        <button id="mutecallbtn" type="button" class="grey" onclick="toggleCallMute()" style="display:none">Mute mic</button>
        <button id="holdcallbtn" type="button" class="grey" onclick="toggleCallHold()" style="display:none">Put on hold</button>
        <button id="hangupcallbtn" type="button" class="grey" onclick="hangupVoiceCall()" style="display:none">Hang up</button>
        <button id="closecallbtn" type="button" class="grey" onclick="closeCallPanel()" style="display:none">Close</button>
      </div>
      <audio id="remoteaudio" autoplay playsinline></audio>
    </div>

    <div id="newspage">
      <div class="dlbar" id="newsbar"></div>
      <div id="newslist"><div class="empty">Loading...</div></div>
    </div>


    <div id="drivepage">
      <div class="dlbar" id="drivebar" style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap"></div>
      <div id="drivehome">
        <div id="drivequota" class="muted"></div>
        <div id="driveupload" style="margin:12px 0">
          <input id="drivefile" type="file">
          <button id="driveuploadbtn" onclick="uploadDriveFile()">Upload file</button>
          <div id="drivestatus" class="editstatus" aria-live="polite"></div>
        </div>
        <div id="drivefiles"><div class="empty">Loading files...</div></div>
      </div>
      <div id="drivemanage" style="display:none">
        <button class="grey" onclick="showDriveHome()">← Back to iLegacy Drive</button>
        <h2>Drive storage settings</h2>
        <div id="drivemyquota" style="background:#fff;border:1px solid #ddd;border-radius:8px;padding:12px;margin:12px 0">
          <h3 style="margin-top:0">My moderator storage</h3>
          <label>My storage quota (MB, 500–76800)</label>
          <input id="drivemyquotaMB" type="number" min="500" max="76800" step="1" value="35840">
          <button onclick="saveMyDriveQuota()">Save my storage</button>
          <div id="drivemyquotastatus" class="editstatus" aria-live="polite"></div>
        </div>
        <div id="drivegrant" style="background:#fff;border:1px solid #ddd;border-radius:8px;padding:12px;margin:12px 0">
          <h3 style="margin-top:0">Assign storage to another user</h3>
          <label>User ID</label>
          <input id="driveuserid" placeholder="IL-12345678">
          <label>Storage quota (MB, 500–76800)</label>
          <input id="drivequotaMB" type="number" min="500" max="76800" step="1" value="2500">
          <button onclick="grantDriveQuota()">Assign storage</button>
          <div id="drivegrantstatus" class="editstatus" aria-live="polite"></div>
        </div>
      </div>
    </div>

    <div id="downloadspage">
      <div class="dlbar" id="dlbar"></div>
      <div id="dllist"><div class="empty">Loading...</div></div>
    </div>

    <div id="profilepage">
      <div id="profilecol">
        <div class="feedinner">
          <div id="profilecard"></div>
          <div id="profposts"></div>
        </div>
      </div>
      <div id="inbox">
        <div id="inboxhead">
          <span>Inbox</span>
          <button class="grey" onclick="markAllRead()">Mark all read</button>
        </div>
        <div id="inboxlist"><div class="empty">Loading...</div></div>
      </div>
    </div>
  </div>
</div>

<div class="modalbg" id="catmodal">
  <div class="modal">
    <h3>Add Category</h3>
    <label for="catname">Category name (for example: iOS 6)</label>
    <input id="catname" maxlength="40" placeholder="Category name">
    <div class="modalstatus" id="caterr"></div>
    <div class="row">
      <button class="grey" onclick="hideModal('catmodal')">Cancel</button>
      <button id="catbtn" onclick="createCategory()">Create</button>
    </div>
  </div>
</div>

<div class="modalbg" id="upmodal">
  <div class="modal">
    <h3 id="upmodaltitle">Upload .deb / .exe</h3>
    <label for="upcat">Category</label>
    <select id="upcat"></select>
    <label for="upfile" id="upfilelabel">.deb or .exe file (max 200 MB)</label>
    <input id="upfile" type="file" accept=".deb,.exe">
    <label for="upname">Package name</label>
    <input id="upname" maxlength="80" placeholder="My Tweak">
    <label for="upauthor">Author</label>
    <input id="upauthor" maxlength="60" placeholder="Author">
    <label for="upbundle">Bundle ID</label>
    <input id="upbundle" maxlength="150" placeholder="com.example.mytweak">
    <label for="upversion">Version number</label>
    <input id="upversion" maxlength="50" placeholder="1.0.0">
    <div class="row" style="margin-top:0">
      <div style="flex:1">
        <label for="upmin">Min iOS (optional)</label>
        <input id="upmin" maxlength="12" placeholder="6.0">
      </div>
      <div style="flex:1">
        <label for="upmax">Max iOS (optional)</label>
        <input id="upmax" maxlength="12" placeholder="6.1.6">
      </div>
    </div>
    <label for="updesc">Description (optional)</label>
    <textarea id="updesc" maxlength="500" placeholder="What does it do?"></textarea>
    <label for="uptag">Special tag (optional)</label>
    <select id="uptag"></select>
    <div class="modalstatus" id="upstatus"></div>
    <div class="row">
      <button class="grey" id="upcancel" onclick="hideModal('upmodal')">Cancel</button>
      <button id="upbtn" onclick="uploadDeb()">Upload</button>
    </div>
  </div>
</div>

<div class="modalbg" id="newsmodal">
  <div class="modal wide">
    <h3 id="newsmodaltitle">New Announcement</h3>
    <label for="ntitle">Title</label>
    <input id="ntitle" maxlength="100" placeholder="Announcement title">

    <label>Message</label>
    <div class="newstools" id="newstools">
      <select id="nfont" onchange="newsFont(this)" title="Font">
        <option value="">Font</option>
        <option value="Arial" style="font-family:Arial">Arial</option>
        <option value="Helvetica" style="font-family:Helvetica">Helvetica</option>
        <option value="Georgia" style="font-family:Georgia">Georgia</option>
        <option value="Times New Roman" style="font-family:'Times New Roman'">Times New Roman</option>
        <option value="Courier New" style="font-family:'Courier New'">Courier New</option>
        <option value="Verdana" style="font-family:Verdana">Verdana</option>
        <option value="Tahoma" style="font-family:Tahoma">Tahoma</option>
        <option value="Trebuchet MS" style="font-family:'Trebuchet MS'">Trebuchet MS</option>
        <option value="Comic Sans MS" style="font-family:'Comic Sans MS'">Comic Sans MS</option>
        <option value="Impact" style="font-family:Impact">Impact</option>
        <option value="Palatino Linotype" style="font-family:'Palatino Linotype'">Palatino</option>
        <option value="Lucida Console" style="font-family:'Lucida Console'">Lucida Console</option>
      </select>
      <select id="nsize" onchange="newsSize(this)" title="Text size">
        <option value="">Size</option>
        <option value="10">10</option>
        <option value="12">12</option>
        <option value="14">14</option>
        <option value="16">16</option>
        <option value="18">18</option>
        <option value="24">24</option>
        <option value="32">32</option>
        <option value="48">48</option>
        <option value="64">64</option>
      </select>
      <button type="button" onclick="newsCmd('bold')" title="Bold"><b>B</b></button>
      <button type="button" onclick="newsCmd('italic')" title="Italic"><i>I</i></button>
      <button type="button" onclick="newsCmd('underline')" title="Underline"><u>U</u></button>
      <button type="button" onclick="newsCmd('strikeThrough')" title="Strikethrough"><s>S</s></button>
      <label title="Text color">Text <input type="color" id="ncolor" value="#dc2626" onchange="newsColor('foreColor', this.value)"></label>
      <label title="Highlight color">Highlight <input type="color" id="nhilite" value="#fde047" onchange="newsColor('hiliteColor', this.value)"></label>
      <button type="button" onclick="newsCmd('justifyLeft')" title="Align left">Left</button>
      <button type="button" onclick="newsCmd('justifyCenter')" title="Center">Center</button>
      <button type="button" onclick="newsCmd('justifyRight')" title="Align right">Right</button>
      <button type="button" onclick="newsCmd('insertUnorderedList')" title="Bullet list">Bullets</button>
      <button type="button" onclick="newsCmd('insertOrderedList')" title="Numbered list">Numbers</button>
      <button type="button" onclick="newsLink()" title="Add link">Link</button>
      <button type="button" onclick="newsCmd('removeFormat')" title="Clear formatting">Clear</button>
    </div>
    <div id="neditor" contenteditable="true"></div>

    <label for="nfiles">Attach images/MP3 (5 MB max), MP4 video (7.5 GB max) or ZIP files (750 MB max) - up to 10 files</label>
    <input id="nfiles" type="file" multiple
           accept="image/jpeg,image/png,image/gif,image/webp,audio/mpeg,audio/wav,audio/ogg,audio/mp4,audio/x-m4a,video/mp4,.mp3,.wav,.ogg,.m4a,.mp4,.zip,application/zip,application/x-zip-compressed">
    <div id="nattach"></div>

    <div class="modalstatus" id="nstatus"></div>
    <div class="row">
      <button class="grey" onclick="hideModal('newsmodal')">Cancel</button>
      <button id="npublish" onclick="publishNews()">Publish</button>
    </div>
  </div>
</div>

<div class="modalbg" id="histmodal">
  <div class="modal wide">
    <h3 id="histtitle">Account history</h3>
    <div class="muted" id="histsub"></div>
    <div id="histbody"><div class="empty">Loading...</div></div>
    <div class="row">
      <button class="grey" onclick="hideModal('histmodal')">Close</button>
    </div>
  </div>
</div>

<script>
var API = location.protocol + '//' + location.host;
var token = localStorage.getItem('il_token');
var me = null;
var current = null;
var es = null;
var shown = {};
var currentPage = 'home';
var viewing = null;

var callState = null;
var callIceServers = [{ urls: 'stun:stun.l.google.com:19302' }];
var incomingCall = null;
var incomingOffer = null;
var pendingIce = [];
var remoteDescriptionSet = false;
var answerInProgress = false;
var callEndingLocally = false;
var callRingTimer = null;
var callToneTimer = null;
var callToneContext = null;
var callToneNodes = [];
var remoteOnHold = false;

function stopCallTone() {
  if (callToneTimer) clearInterval(callToneTimer);
  callToneTimer = null;
  callToneNodes.forEach(function (node) { try { node.stop(); } catch (_) {} });
  callToneNodes = [];
}

function playToneBurst(frequencies, durationMs) {
  try {
    var AudioContextCtor = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextCtor) return;
    if (!callToneContext) callToneContext = new AudioContextCtor();
    if (callToneContext.state === 'suspended') callToneContext.resume().catch(function () {});
    var startAt = callToneContext.currentTime;
    frequencies.forEach(function (frequency, index) {
      var oscillator = callToneContext.createOscillator();
      var gain = callToneContext.createGain();
      oscillator.type = 'sine';
      oscillator.frequency.value = frequency;
      gain.gain.setValueAtTime(0.0001, startAt);
      gain.gain.exponentialRampToValueAtTime(0.12, startAt + 0.025);
      gain.gain.setValueAtTime(0.12, startAt + Math.max(0.04, durationMs / 1000 - 0.035));
      gain.gain.exponentialRampToValueAtTime(0.0001, startAt + durationMs / 1000);
      oscillator.connect(gain); gain.connect(callToneContext.destination);
      oscillator.start(startAt); oscillator.stop(startAt + durationMs / 1000 + 0.01);
      callToneNodes.push(oscillator);
      oscillator.onended = function () { callToneNodes = callToneNodes.filter(function (n) { return n !== oscillator; }); };
    });
  } catch (err) { console.warn('Call tone could not play:', err.message); }
}

function startCallTone(kind) {
  stopCallTone();
  if (kind === 'hangup') {
    playToneBurst([480, 620], 180);
    setTimeout(function () { playToneBurst([480, 620], 180); }, 220);
    return;
  }
  var cadence = kind === 'incoming' ? 2000 : 2600;
  var play = function () {
    if (kind === 'incoming') {
      playToneBurst([440, 480], 420);
      setTimeout(function () { playToneBurst([440, 480], 420); }, 520);
    } else {
      playToneBurst([425], 350);
      setTimeout(function () { playToneBurst([425], 350); }, 520);
    }
  };
  play();
  callToneTimer = setInterval(play, cadence);
}

function updateCallControls() {
  var active = !!(callState && callState.localStream);
  $('mutecallbtn').style.display = active ? '' : 'none';
  $('holdcallbtn').style.display = active ? '' : 'none';
  $('mutecallbtn').textContent = active && callState.muted ? 'Unmute mic' : 'Mute mic';
  $('holdcallbtn').textContent = active && callState.onHold ? 'Resume call' : 'Put on hold';
}

function callPanel(title, status, buttons) {
  $('calltitle').textContent = title || 'iLegacy Calling';
  $('callstatus').textContent = status || '';
  $('callpanel').style.display = 'block';
  $('answercallbtn').style.display = buttons && buttons.answer ? '' : 'none';
  $('declinecallbtn').style.display = buttons && buttons.decline ? '' : 'none';
  $('hangupcallbtn').style.display = buttons && buttons.hangup ? '' : 'none';
  $('closecallbtn').style.display = buttons && buttons.close ? '' : 'none';
  updateCallControls();
}

function closeCallPanel() {
  if (callState || incomingCall) return;
  $('callpanel').style.display = 'none';
}

function stopCallMedia() {
  stopPCMBridge();
  stopCallTone();
  if (callState && callState.pc) {
    try { callState.pc.onicecandidate = null; callState.pc.ontrack = null; callState.pc.close(); } catch (_) {}
  }
  if (callState && callState.localStream) {
    callState.localStream.getTracks().forEach(function (track) { track.stop(); });
  }
  $('remoteaudio').srcObject = null;
  $('remoteaudio').muted = false;
  callState = null;
  incomingCall = null;
  incomingOffer = null;
  pendingIce = [];
  remoteDescriptionSet = false;
  answerInProgress = false;
  remoteOnHold = false;
  if (callRingTimer) clearTimeout(callRingTimer);
  callRingTimer = null;
}

function resetCallUi(status) {
  stopCallMedia();
  callPanel('iLegacy Calling', status || 'Call ended', { close: true });
  startCallTone('hangup');
}

function postCallSignal(signal) {
  if (!callState || !callState.callId) return Promise.reject(new Error('No active call'));
  return api('POST', '/calls/' + encodeURIComponent(callState.callId) + '/signal', { signal: signal });
}

var pcmContext = null, pcmProcessor = null, pcmSource = null, pcmMicStream = null;
var pcmOutQueue = [], pcmPlaybackSamples = [], pcmSendPending = false, pcmCarry = [];
function stopPCMBridge() {
  try { if (pcmProcessor) { pcmProcessor.disconnect(); pcmProcessor.onaudioprocess = null; } } catch (_) {}
  try { if (pcmSource) pcmSource.disconnect(); } catch (_) {}
  try { if (pcmContext) pcmContext.close(); } catch (_) {}
  pcmContext = pcmProcessor = pcmSource = null;
  pcmOutQueue = []; pcmPlaybackSamples = []; pcmCarry = []; pcmSendPending = false;
}
function pcmEncode8k(input, sourceRate) {
  var step = sourceRate / 8000, out = [];
  for (var i = 0; i < input.length; i += step) {
    var sample = input[Math.floor(i)] || 0;
    out.push(Math.max(-32768, Math.min(32767, Math.round(sample * (sample < 0 ? 32768 : 32767)))));
  }
  var bytes = new Uint8Array(out.length * 2);
  for (var j = 0; j < out.length; j++) { bytes[j*2] = out[j] & 255; bytes[j*2+1] = (out[j] >> 8) & 255; }
  return bytes;
}
function pcmDecode8k(base64) {
  var raw = atob(base64 || ''), out = new Float32Array(Math.floor(raw.length / 2));
  for (var i = 0; i < out.length; i++) {
    var n = raw.charCodeAt(i*2) | (raw.charCodeAt(i*2+1) << 8);
    if (n & 0x8000) n -= 65536;
    out[i] = n / 32768;
  }
  return out;
}
function startPCMBridge() {
  if (!callState || !callState.localStream || callState.pcm) return;
  var AC = window.AudioContext || window.webkitAudioContext;
  if (!AC || !window.atob) { callPanel('iLegacy Calling', 'This browser cannot bridge legacy audio.', { hangup: true }); return; }
  stopPCMBridge();
  try {
    pcmContext = new AC();
    pcmSource = pcmContext.createMediaStreamSource(callState.localStream);
    pcmProcessor = pcmContext.createScriptProcessor(4096, 1, 1);
    callState.pcm = true;
    pcmProcessor.onaudioprocess = function (ev) {
      if (!callState || !callState.pcm) return;
      var out = ev.outputBuffer.getChannelData(0);
      for (var z=0; z<out.length; z++) out[z] = 0;
      if (!callState.onHold) {
        var input = ev.inputBuffer.getChannelData(0);
        var bytes = pcmEncode8k(input, pcmContext.sampleRate);
        if (!callState.muted && bytes.length) {
          for (var b=0; b<bytes.length; b++) pcmCarry.push(bytes[b]);
          while (pcmCarry.length >= 1600) {
            var chunk = pcmCarry.splice(0, 1600);
            var bin = ''; for (var q=0; q<chunk.length; q++) bin += String.fromCharCode(chunk[q]);
            pcmOutQueue.push(btoa(bin));
            if (pcmOutQueue.length > 10) pcmOutQueue.splice(0, pcmOutQueue.length - 10);
          }
          sendPCMQueue();
        }
      }
      if (!callState.onHold && pcmPlaybackSamples.length) {
        var ratio = pcmContext.sampleRate / 8000;
        var consumed = Math.min(pcmPlaybackSamples.length, Math.ceil(out.length / ratio));
        for (var y=0; y<out.length; y++) {
          var ix = Math.floor(y / ratio);
          if (ix < pcmPlaybackSamples.length) out[y] = pcmPlaybackSamples[ix];
        }
        pcmPlaybackSamples.splice(0, consumed);
      }
    };
    pcmSource.connect(pcmProcessor);
    pcmProcessor.connect(pcmContext.destination);
    if (pcmContext.resume) pcmContext.resume();
    callPanel('iLegacy Calling', 'Connected — legacy audio link active', { hangup: true });
  } catch (e) {
    console.error('Legacy audio bridge failed:', e);
    callPanel('iLegacy Calling', 'Legacy audio setup failed: ' + e.message, { hangup: true });
  }
}
function sendPCMQueue() {
  if (pcmSendPending || !pcmOutQueue.length || !callState || !callState.pcm) return;
  pcmSendPending = true;
  var data = pcmOutQueue.shift();
  postCallSignal({ type: 'audio', rate: 8000, data: data }).catch(function (err) {
    console.warn('Could not send legacy audio:', err.message);
  }).then(function () { pcmSendPending = false; sendPCMQueue(); });
}

function createCallPeer() {
  if (!callState) throw new Error('No active call');
  var pc = new RTCPeerConnection({ iceServers: callIceServers });
  callState.pc = pc;
  callState.localStream.getTracks().forEach(function (track) {
    pc.addTrack(track, callState.localStream);
  });
  pc.onicecandidate = function (event) {
    if (event.candidate) {
      postCallSignal({ type: 'ice', candidate: event.candidate }).catch(function (err) {
        console.warn('Could not send ICE candidate:', err.message);
      });
    }
  };
  pc.ontrack = function (event) {
    var audio = $('remoteaudio');
    if (event.streams && event.streams[0]) audio.srcObject = event.streams[0];
    audio.play().catch(function () {});
    callPanel('iLegacy Calling', remoteOnHold ? 'Connected — the other person is on hold' : (callState && callState.onHold ? 'You put this call on hold' : 'Connected — microphone audio is live'), { hangup: true });
  };
  pc.onconnectionstatechange = function () {
    if (!callState || callState.pc !== pc) return;
    if (pc.connectionState === 'connected') {
      callPanel('iLegacy Calling', remoteOnHold ? 'Connected — the other person is on hold' : (callState && callState.onHold ? 'You put this call on hold' : 'Connected — microphone audio is live'), { hangup: true });
    } else if (pc.connectionState === 'failed' || pc.connectionState === 'disconnected') {
      callPanel('iLegacy Calling', 'Connection interrupted. You can hang up and try again.', { hangup: true });
    }
  };
  return pc;
}

function applyQueuedIce(pc) {
  if (!remoteDescriptionSet) return Promise.resolve();
  var queue = pendingIce.slice();
  pendingIce = [];
  return queue.reduce(function (chain, candidate) {
    return chain.then(function () { return pc.addIceCandidate(new RTCIceCandidate(candidate)); });
  }, Promise.resolve());
}

function startVoiceCall() {
  if (!current || callState || incomingCall) return;
  if (!window.RTCPeerConnection || !navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    alert('Voice calling requires a modern WebRTC browser and HTTPS (or localhost) for microphone access.');
    return;
  }
  var target = current;
  $('callbtn').disabled = true;
  startCallTone('dialing');
  callPanel('Calling ' + target.displayName, 'Requesting a call…', { hangup: true });
  api('GET', '/calls/config').then(function (config) {
    if (Array.isArray(config.iceServers) && config.iceServers.length) callIceServers = config.iceServers;
    return api('POST', '/calls/invite', { to: target.userId });
  }).then(function (data) {
    callState = { callId: data.call.callId, peerId: target.userId, direction: 'outgoing', localStream: null, pc: null, muted: false, onHold: false };
    callPanel('Calling ' + target.displayName, 'Waiting for them to answer…', { hangup: true });
    return navigator.mediaDevices.getUserMedia({ audio: true, video: false });
  }).then(function (stream) {
    if (!callState) { stream.getTracks().forEach(function (t) { t.stop(); }); return; }
    callState.localStream = stream;
    var pc = createCallPeer();
    return pc.createOffer().then(function (offer) {
      return pc.setLocalDescription(offer).then(function () {
        return postCallSignal({ type: 'offer', description: pc.localDescription });
      });
    });
  }).catch(function (err) {
    var id = callState && callState.callId;
    if (id) api('POST', '/calls/' + encodeURIComponent(id) + '/end', {}).catch(function () {});
    resetCallUi('Could not start call: ' + (err.message || 'microphone unavailable'));
    $('callbtn').disabled = !current;
  });
}

function answerVoiceCall() {
  if (!incomingCall || answerInProgress) return;
  answerInProgress = true;
  var call = incomingCall;
  if (callRingTimer) clearTimeout(callRingTimer);
  callRingTimer = null;
  stopCallTone();
  callPanel('Incoming call from ' + call.from.displayName, 'Allow microphone access to answer.', { hangup: true });
  api('GET', '/calls/config').then(function (config) {
    if (Array.isArray(config.iceServers) && config.iceServers.length) callIceServers = config.iceServers;
    return navigator.mediaDevices.getUserMedia({ audio: true, video: false });
  }).then(function (stream) {
    if (!incomingCall || incomingCall.callId !== call.callId) {
      stream.getTracks().forEach(function (t) { t.stop(); });
      return;
    }
    callState = { callId: call.callId, peerId: call.from.userId, direction: 'incoming', localStream: stream, pc: null, muted: false, onHold: false };
    return api('POST', '/calls/' + encodeURIComponent(call.callId) + '/accept', {})
      .then(function () {
        if (incomingOffer) return processIncomingOffer();
        callPanel('iLegacy Calling', 'Connecting…', { hangup: true });
      });
  }).catch(function (err) {
    api('POST', '/calls/' + encodeURIComponent(call.callId) + '/decline', {}).catch(function () {});
    resetCallUi('Could not answer: ' + (err.message || 'microphone unavailable'));
  }).then(function () { answerInProgress = false; });
}

function processIncomingOffer() {
  stopCallTone();
  if (!callState || !callState.localStream || !incomingOffer || callState.pc) return Promise.resolve();
  var offer = incomingOffer;
  incomingOffer = null;
  var pc = createCallPeer();
  return pc.setRemoteDescription(new RTCSessionDescription(offer)).then(function () {
    remoteDescriptionSet = true;
    return applyQueuedIce(pc);
  }).then(function () {
    return pc.createAnswer();
  }).then(function (answer) {
    return pc.setLocalDescription(answer).then(function () {
      return postCallSignal({ type: 'answer', description: pc.localDescription });
    });
  }).then(function () {
    callPanel('iLegacy Calling', 'Connecting audio…', { hangup: true });
  }).catch(function (err) {
    console.error('Could not answer WebRTC offer:', err);
    hangupVoiceCall();
    callPanel('iLegacy Calling', 'Call setup failed: ' + err.message, { close: true });
  });
}

function toggleCallMute() {
  if (!callState || !callState.localStream) return;
  callState.muted = !callState.muted;
  callState.localStream.getAudioTracks().forEach(function (track) {
    track.enabled = !callState.muted && !callState.onHold;
  });
  updateCallControls();
  postCallSignal({ type: 'mute', muted: callState.muted }).catch(function (err) {
    console.warn('Could not notify the other caller about mute:', err.message);
  });
  if (callState.onHold) $('callstatus').textContent = 'You put this call on hold';
  else $('callstatus').textContent = callState.muted ? 'Microphone muted' : (remoteOnHold ? 'The other person is on hold' : 'Connected — microphone audio is live');
}

function toggleCallHold() {
  if (!callState || !callState.localStream) return;
  callState.onHold = !callState.onHold;
  callState.localStream.getAudioTracks().forEach(function (track) {
    track.enabled = !callState.muted && !callState.onHold;
  });
  $('remoteaudio').muted = callState.onHold;
  postCallSignal({ type: 'hold', held: callState.onHold }).catch(function (err) {
    console.warn('Could not notify the other caller about hold:', err.message);
  });
  updateCallControls();
  $('callstatus').textContent = callState.onHold ? 'Call on hold — microphone and incoming audio paused' : (remoteOnHold ? 'Resumed — the other person is still on hold' : (callState.muted ? 'Resumed — microphone remains muted' : 'Call resumed'));
}

function declineVoiceCall() {
  if (!incomingCall) return;
  var id = incomingCall.callId;
  api('POST', '/calls/' + encodeURIComponent(id) + '/decline', {}).catch(function () {});
  resetCallUi('Call declined');
  $('callbtn').disabled = !current;
}

function hangupVoiceCall() {
  var id = callState && callState.callId || incomingCall && incomingCall.callId;
  callEndingLocally = true;
  if (id) api('POST', '/calls/' + encodeURIComponent(id) + '/end', {}).catch(function () {});
  resetCallUi('Call ended');
  callEndingLocally = false;
  $('callbtn').disabled = !current;
}

function handleCallInvite(data) {
  if (callState || incomingCall) {
    api('POST', '/calls/' + encodeURIComponent(data.callId) + '/decline', {}).catch(function () {});
    return;
  }
  if (!window.RTCPeerConnection || !navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    api('POST', '/calls/' + encodeURIComponent(data.callId) + '/decline', {}).catch(function () {});
    callPanel('Incoming call', 'This browser does not support microphone calling.', { close: true });
    return;
  }
  incomingCall = data;
  incomingOffer = null;
  startCallTone('incoming');
  pendingIce = [];
  $('callbtn').disabled = true;
  callPanel('Incoming call from ' + data.from.displayName, 'Incoming voice call', { answer: true, decline: true });
  callRingTimer = setTimeout(function () {
    if (incomingCall && incomingCall.callId === data.callId) resetCallUi('Missed call');
  }, 45000);
}

function handleCallSignal(data) {
  if (incomingCall && data.callId === incomingCall.callId && !callState) {
    if (data.signal && data.signal.type === 'offer') incomingOffer = data.signal.description;
    else if (data.signal && data.signal.type === 'ice' && data.signal.candidate) pendingIce.push(data.signal.candidate);
    return;
  }
  if (!callState || data.callId !== callState.callId || !data.signal) return;
  var signal = data.signal;
  if (signal.type === 'native_audio') {
    if (callState.pc) { try { callState.pc.close(); } catch (_) {} callState.pc = null; }
    startPCMBridge();
  } else if (signal.type === 'audio' && callState.pcm && signal.data) {
    if (!callState.onHold) {
      var decoded = pcmDecode8k(signal.data);
      for (var ai=0; ai<decoded.length; ai++) pcmPlaybackSamples.push(decoded[ai]);
      if (pcmPlaybackSamples.length > 12000) pcmPlaybackSamples.splice(0, pcmPlaybackSamples.length - 12000);
    }
  } else if (signal.type === 'answer' && signal.description && callState.pc) {
    stopCallTone();
    callState.pc.setRemoteDescription(new RTCSessionDescription(signal.description)).then(function () {
      remoteDescriptionSet = true;
      return applyQueuedIce(callState.pc);
    }).catch(function (err) { console.error('Could not set remote answer:', err); });
  } else if (signal.type === 'offer' && signal.description && callState.direction === 'incoming') {
    incomingOffer = signal.description;
    processIncomingOffer();
  } else if (signal.type === 'ice' && signal.candidate) {
    if (callState.pc && remoteDescriptionSet) {
      callState.pc.addIceCandidate(new RTCIceCandidate(signal.candidate)).catch(function (err) {
        console.warn('Could not add ICE candidate:', err.message);
      });
    } else {
      pendingIce.push(signal.candidate);
    }
  } else if (signal.type === 'hold') {
    remoteOnHold = !!signal.held;
    if (callState) {
      $('callstatus').textContent = remoteOnHold ? 'The other person put the call on hold' : (callState.onHold ? 'You put this call on hold' : 'The other person resumed the call');
    }
  } else if (signal.type === 'mute') {
    if (callState) {
      callState.remoteMuted = !!signal.muted;
      $('callstatus').textContent = callState.remoteMuted ? 'The other person muted their microphone' : (remoteOnHold ? 'The other person put the call on hold' : (callState.onHold ? 'You put this call on hold' : (callState.muted ? 'Microphone muted' : 'Connected — microphone audio is live')));
    }
  }
}

function handleCallEnded(data) {
  if ((callState && callState.callId === data.callId) ||
      (incomingCall && incomingCall.callId === data.callId)) {
    if (callEndingLocally) return;
    var reason = data.reason === 'declined' ? 'Call declined' :
      data.reason === 'timeout' ? 'No answer' : 'Call ended by the other user';
    resetCallUi(reason);
    $('callbtn').disabled = !current;
  }
}

function $(id) {
  return document.getElementById(id);
}

function el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}

function api(method, endpoint, body) {
  var headers = {};

  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  if (token) {
    headers['Authorization'] = 'Bearer ' + token;
  }

  return fetch(API + endpoint, {
    method: method,
    headers: headers,
    body: body !== undefined ? JSON.stringify(body) : undefined
  }).then(function (response) {
    return response.json().then(function (data) {
      if (!response.ok) {
        throw new Error(data.error || 'Something went wrong');
      }

      return data;
    });
  });
}

function formatTime(ts) {
  try {
    return new Date(ts).toLocaleString();
  } catch (err) {
    return '';
  }
}

function avatar(user, size) {
  var box;

  if (user && user.avatarUrl) {
    box = document.createElement('img');
    box.src = API + user.avatarUrl;
    box.alt = '';
    box.className = 'avatar';
  } else {
    var letter = ((user && (user.displayName || user.username)) || '?')
      .charAt(0).toUpperCase();
    box = el('div', 'avatar avatar-ph', letter);
  }

  box.style.width = size + 'px';
  box.style.height = size + 'px';
  box.style.fontSize = Math.round(size / 2) + 'px';
  return box;
}

function doAuth(kind) {
  var name = $('u').value.trim();
  var password = $('p').value;

  var body = { password: password };

  if (kind === 'register') {
    body.username = name;
  } else if (/^IL-/i.test(name)) {
    body.userId = name.toUpperCase();
  } else {
    body.username = name;
  }

  $('err').textContent = '';

  api('POST', '/' + kind, body).then(function (data) {
    token = data.token;
    localStorage.setItem('il_token', token);
    showApp(data.user);
  }).catch(function (err) {
    $('err').textContent = err.message;
  });
}

function showApp(user) {
  me = user;
  viewing = null;
  $('auth').style.display = 'none';
  $('app').style.display = 'flex';
  $('myname').textContent = user.displayName;
  $('myid').textContent = user.userId;
  api('GET', '/profiles/' + encodeURIComponent(user.userId)).then(function (data) {
    if (data.profile && data.profile.isMe) applyDarkMode(!!data.profile.darkMode);
  }).catch(function () {});

  loadConvos();
  connectStream();
  refreshBadge();
  showPage('home');
}

function logout() {
  api('POST', '/logout').catch(function () {}).then(function () {
    localStorage.removeItem('il_token');

    token = null;
    me = null;
    current = null;
    viewing = null;

    if (es) {
      es.close();
      es = null;
    }

    $('app').style.display = 'none';
    $('auth').style.display = 'block';
    $('p').value = '';
  });
}

function toggleMobileNav() {
  var bar = $('topbar');
  var button = $('mobilemenubtn');
  var open = bar.classList.toggle('menu-open');
  button.setAttribute('aria-expanded', open ? 'true' : 'false');
  button.innerHTML = open ? '<span aria-hidden="true">×</span> Close menu' : '<span aria-hidden="true">☰</span> Menu';
}

function closeMobileNav() {
  var bar = $('topbar');
  var button = $('mobilemenubtn');
  if (!bar || !button) return;
  bar.classList.remove('menu-open');
  button.setAttribute('aria-expanded', 'false');
  button.innerHTML = '<span aria-hidden="true">☰</span> Menu';
}

function showPage(page) {
  closeMobileNav();
  currentPage = page;
  $('side').style.display = page === 'messages' ? 'flex' : 'none';
  if (window.matchMedia && window.matchMedia('(min-width: 901px)').matches) {
    $('workspace').style.left = page === 'messages' ? '290px' : '0';
  } else {
    $('workspace').style.left = '';
  }

  $('feed').style.display = page === 'home' ? 'block' : 'none';
  $('chatview').style.display = page === 'messages' ? 'flex' : 'none';
  $('chattools').style.display = page === 'messages' ? 'flex' : 'none';
  $('profilepage').style.display = page === 'profile' ? 'flex' : 'none';
  $('downloadspage').style.display = page === 'downloads' ? 'flex' : 'none';
  $('newspage').style.display = page === 'news' ? 'flex' : 'none';
  $('drivepage').style.display = page === 'drive' ? 'flex' : 'none';

  $('homeTab').className = page === 'home' ? '' : 'grey';
  $('messagesTab').className = page === 'messages' ? '' : 'grey';
  $('profileTab').className = page === 'profile' ? '' : 'grey';
  $('downloadsTab').className = page === 'downloads' ? '' : 'grey';
  $('newsTab').className = (page === 'news' ? '' : 'grey') + ' wide';
  $('driveTab').className = (page === 'drive' ? '' : 'grey') + ' wide';

  if (page === 'home') loadPosts();
  if (page === 'downloads') loadDownloads();
  if (page === 'news') loadNews();
  if (page === 'drive') loadDrive();

  if (page === 'profile') {
    loadProfile(viewing || me.userId);
    loadInbox();
  }
}

function openProfile(userId) {
  viewing = userId || me.userId;
  showPage('profile');
}

function userLink(user) {
  var b = el('button', 'linklike', user.displayName);
  b.onclick = function () { openProfile(user.userId); };
  return b;
}

function formatDriveSize(bytes) {
  bytes = Number(bytes) || 0;
  if (bytes >= 1024 * 1024 * 1024) return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
  if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return bytes + ' bytes';
}

function loadDrive() {
  $('drivebar').innerHTML = '';
  $('drivebar').appendChild(el('h2', null, 'iLegacy Drive'));
  if (me && me.isAdmin) {
    var manage = el('button', null, 'Assign storage');
    manage.style.marginLeft = 'auto';
    manage.onclick = showDriveManage;
    $('drivebar').appendChild(manage);
  }
  $('drivehome').style.display = 'block';
  $('drivemanage').style.display = 'none';
  $('drivefiles').innerHTML = '<div class="empty">Loading files...</div>';
  api('GET', '/drive').then(function (data) {
    $('drivequota').textContent = formatDriveSize(data.usedBytes) + ' used of ' +
      formatDriveSize(data.quotaBytes) + ' (' +
      Math.max(0, Math.min(100, data.usedBytes / Math.max(1, data.quotaBytes) * 100)).toFixed(1) + '%)';
    if (data.isModerator) $('drivemyquotaMB').value = Math.round(data.quotaBytes / (1024 * 1024));
    renderDriveFiles(data.files || []);
  }).catch(function (err) {
    $('drivefiles').textContent = 'Could not load Drive: ' + err.message;
  });
}

function showDriveManage() {
  $('drivehome').style.display = 'none';
  $('drivemanage').style.display = 'block';
  $('drivemyquotastatus').textContent = '';
  $('drivegrantstatus').textContent = '';
}

function showDriveHome() {
  $('drivemanage').style.display = 'none';
  $('drivehome').style.display = 'block';
  loadDrive();
}

function saveMyDriveQuota() {
  var status = $('drivemyquotastatus');
  var mb = Number($('drivemyquotaMB').value);
  status.style.color = '#c0392b';
  if (!Number.isInteger(mb) || mb < 500 || mb > 76800) {
    status.textContent = 'Choose a quota from 500 to 76800 MB.';
    return;
  }
  api('POST', '/drive/quota', { userId: me.userId, quotaBytes: mb * 1024 * 1024 })
    .then(function (data) {
      status.style.color = '#18794e';
      status.textContent = 'Your Drive storage is now ' + formatDriveSize(data.quotaBytes) + '.';
      loadDrive();
    }).catch(function (err) {
      status.textContent = err.message;
    });
}

function renderDriveFiles(files) {
  var box = $('drivefiles');
  box.innerHTML = '';
  if (!files.length) {
    box.appendChild(el('div', 'empty', 'Your iLegacy Drive is empty. Upload any file to get started.'));
    return;
  }
  files.forEach(function (file) {
    var row = el('div');
    row.style.cssText = 'display:flex;gap:12px;align-items:center;background:#fff;border:1px solid #ddd;border-radius:8px;padding:12px;margin:8px 0;flex-wrap:wrap';
    var info = el('div');
    info.style.cssText = 'flex:1;min-width:180px;overflow-wrap:anywhere';
    info.appendChild(el('b', null, file.name));
    info.appendChild(el('div', 'muted', formatDriveSize(file.size) + ' · ' + new Date(file.uploadedAt).toLocaleString()));
    var download = el('a', 'btnlink', 'Download');
    download.href = API + '/drive/files/' + encodeURIComponent(file.id) + '/download?token=' + encodeURIComponent(token);
    download.setAttribute('download', file.name);
    var del = el('button', 'act', 'Delete');
    del.onclick = function () {
      if (!confirm('Permanently delete "' + file.name + '" from your Drive?')) return;
      del.disabled = true;
      api('POST', '/drive/files/' + encodeURIComponent(file.id) + '/delete')
        .then(loadDrive).catch(function (err) { del.disabled = false; alert(err.message); });
    };
    row.appendChild(info);
    row.appendChild(download);
    row.appendChild(del);
    box.appendChild(row);
  });
}

function uploadDriveFile() {
  var file = $('drivefile').files && $('drivefile').files[0];
  var status = $('drivestatus');
  if (!file) { status.textContent = 'Choose a file first.'; return; }
  var button = $('driveuploadbtn');
  button.disabled = true;
  status.style.color = '#65676b';
  status.textContent = 'Uploading... 0%';
  var xhr = new XMLHttpRequest();
  xhr.open('POST', API + '/drive/upload?name=' + encodeURIComponent(file.name));
  xhr.setRequestHeader('Authorization', 'Bearer ' + token);
  xhr.setRequestHeader('Content-Type', file.type || 'application/octet-stream');
  xhr.upload.onprogress = function (event) {
    if (event.lengthComputable) status.textContent = 'Uploading... ' + Math.round(event.loaded / event.total * 100) + '%';
  };
  xhr.onload = function () {
    var data = {};
    try { data = JSON.parse(xhr.responseText); } catch (e) {}
    button.disabled = false;
    if (xhr.status >= 200 && xhr.status < 300) {
      $('drivefile').value = '';
      status.textContent = 'Upload complete.';
      loadDrive();
    } else {
      status.style.color = '#c0392b';
      status.textContent = data.error || 'Upload failed.';
    }
  };
  xhr.onerror = function () {
    button.disabled = false;
    status.style.color = '#c0392b';
    status.textContent = 'Upload failed. Check your connection and server upload limits.';
  };
  xhr.send(file);
}

function grantDriveQuota() {
  var status = $('drivegrantstatus');
  var userId = $('driveuserid').value.trim().toUpperCase();
  var mb = Number($('drivequotaMB').value);
  status.textContent = '';
  if (!userId || !Number.isInteger(mb) || mb < 500 || mb > 76800) {
    status.textContent = 'Enter a user ID and a quota from 500 to 76800 MB.';
    return;
  }
  api('POST', '/drive/quota', { userId: userId, quotaBytes: mb * 1024 * 1024 })
    .then(function () {
      status.style.color = '#18794e';
      status.textContent = 'Storage quota updated for ' + userId + '.';
      $('driveuserid').value = '';
      loadDrive();
    }).catch(function (err) {
      status.style.color = '#c0392b';
      status.textContent = err.message;
    });
}

function heartText(post) {
  return (post.liked ? '\\u2665 ' : '\\u2661 ') + post.likeCount;
}

function renderPost(post) {
  var article = el('article', 'feedpost');

  var head = el('div', 'feedposthead');
  head.appendChild(avatar(post.user, 38));

  var who = el('div');
  who.appendChild(userLink(post.user));
  who.appendChild(el('small', null,
    '@' + post.user.username + ' (' + post.user.userId + ') - ' +
    formatTime(post.ts)));
  head.appendChild(who);
  article.appendChild(head);

  if (post.mediaId && post.mediaKind) {
    var mediaUrl = API + '/social/media/' + encodeURIComponent(post.mediaId) +
      '?token=' + encodeURIComponent(token);
    var mediaEl;
    if (post.mediaKind === 'video') {
      mediaEl = document.createElement('video');
      mediaEl.controls = true;
      mediaEl.playsInline = true;
      mediaEl.preload = 'metadata';
    } else if (post.mediaKind === 'audio') {
      mediaEl = document.createElement('audio');
      mediaEl.controls = true;
      mediaEl.preload = 'metadata';
    } else {
      mediaEl = document.createElement('img');
      mediaEl.alt = post.caption || 'Photo posted to iLegacy';
      mediaEl.loading = 'lazy';
    }
    mediaEl.className = 'socialmedia' + (post.mediaKind === 'image' ? ' postimg' : '');
    mediaEl.src = mediaUrl;
    article.appendChild(mediaEl);
  } else if (post.imageUrl) {
    var img = document.createElement('img');
    img.className = 'postimg';
    img.src = API + post.imageUrl;
    img.alt = post.caption || 'Photo posted to iLegacy';
    img.loading = 'lazy';
    article.appendChild(img);
  }

  if (post.caption) {
    article.appendChild(el('div', 'feedcaption', post.caption));
  }

  var actions = el('div', 'actions');
  var likeBtn = el('button', 'act' + (post.liked ? ' on' : ''), heartText(post));
  var cBtn = el('button', 'act', 'Comments ' + post.commentCount);
  actions.appendChild(likeBtn);
  actions.appendChild(cBtn);
  if (me && me.isAdmin) {
    var deleteBtn = el('button', 'act', 'Delete post');
    deleteBtn.onclick = function () {
      var reason = prompt('Reason for deleting this post (required, max 500 characters):', '');
      if (reason === null) return;
      reason = reason.trim();
      if (!reason || reason.length > 500) { alert('Please enter a reason between 1 and 500 characters.'); return; }
      if (!confirm('Delete this post and its comments? This cannot be undone.')) return;
      deleteBtn.disabled = true;
      api('POST', '/admin/posts/' + encodeURIComponent(post.id) + '/delete', { reason: reason })
        .then(function () { showPage(currentPage); })
        .catch(function (err) { deleteBtn.disabled = false; alert(err.message || String(err)); });
    };
    actions.appendChild(deleteBtn);
  }
  article.appendChild(actions);

  likeBtn.onclick = function () {
    api('POST', '/posts/' + encodeURIComponent(post.id) +
      (post.liked ? '/unlike' : '/like')).then(function (d) {
      post.liked = d.liked;
      post.likeCount = d.likeCount;
      likeBtn.textContent = heartText(post);
      likeBtn.className = 'act' + (post.liked ? ' on' : '');
    }).catch(function (e) { alert(e.message); });
  };

  var cBox = el('div', 'comments');
  cBox.style.display = 'none';
  var list = el('div');
  var form = el('div', 'cform');
  var input = document.createElement('input');
  input.placeholder = 'Write a comment...';
  input.maxLength = 500;
  var sendBtn = el('button', null, 'Post');
  form.appendChild(input);
  form.appendChild(sendBtn);
  cBox.appendChild(list);
  cBox.appendChild(form);
  article.appendChild(cBox);

  var loaded = false;

  function updateCount(n) {
    post.commentCount = n;
    cBtn.textContent = 'Comments ' + n;
  }

  function addComment(c) {
    var row = el('div', 'comment');
    row.appendChild(avatar(c.user, 28));

    var body = el('div', 'cbody');
    var line = el('div');
    line.appendChild(userLink(c.user));
    line.appendChild(document.createTextNode(' '));
    line.appendChild(el('small', null,
      '@' + c.user.username + ' (' + c.user.userId + ')'));
    body.appendChild(line);
    body.appendChild(el('div', 'ctext', c.text));
    row.appendChild(body);

    if (c.user.userId === me.userId || post.user.userId === me.userId) {
      var del = el('button', 'x', 'Delete');
      del.onclick = function () {
        api('POST', '/comments/' + encodeURIComponent(c.id) + '/delete')
          .then(function (d) {
            if (row.parentNode) row.parentNode.removeChild(row);
            updateCount(d.commentCount);
          }).catch(function (e) { alert(e.message); });
      };
      row.appendChild(del);
    }

    list.appendChild(row);
  }

  cBtn.onclick = function () {
    var open = cBox.style.display === 'none';
    cBox.style.display = open ? 'block' : 'none';

    if (open && !loaded) {
      loaded = true;
      api('GET', '/posts/' + encodeURIComponent(post.id) + '/comments')
        .then(function (d) {
          list.innerHTML = '';
          d.comments.forEach(addComment);
        }).catch(function (e) {
          list.textContent = 'Could not load comments: ' + e.message;
        });
    }
  };

  function submitComment() {
    var text = input.value.trim();
    if (!text) return;

    sendBtn.disabled = true;

    api('POST', '/posts/' + encodeURIComponent(post.id) + '/comments',
      { text: text }).then(function (d) {
      input.value = '';
      addComment(d.comment);
      updateCount(d.commentCount);
    }).catch(function (e) {
      alert(e.message);
    }).then(function () {
      sendBtn.disabled = false;
    });
  }

  sendBtn.onclick = submitComment;
  input.addEventListener('keydown', function (event) {
    if (event.key === 'Enter') submitComment();
  });

  return article;
}

function renderPostList(box, posts, emptyText) {
  box.innerHTML = '';

  if (!posts.length) {
    box.appendChild(el('div', 'empty', emptyText));
    return;
  }

  posts.forEach(function (post) {
    box.appendChild(renderPost(post));
  });
}

function loadPosts() {
  api('GET', '/posts').then(function (data) {
    renderPostList($('posts'), data.posts,
      'No posts yet. Be the first to share a photo!');
  }).catch(function (err) {
    $('posts').textContent = 'Could not load feed: ' + err.message;
  });
}

$('postform').addEventListener('submit', function (event) {
  event.preventDefault();
  var file = $('imagefile').files[0];
  var caption = $('caption').value;
  if (!file) { $('feedstatus').textContent = 'Choose a photo, GIF, MP3, or MP4 first.'; return; }
  if (caption.length > 1000) { $('feedstatus').textContent = 'Caption must be 1000 characters or fewer.'; return; }
  var fileProblem = checkMediaFile(file, false);
  if (fileProblem) { $('feedstatus').textContent = fileProblem; return; }
  $('publishbtn').disabled = true;
  $('feedstatus').textContent = 'Uploading media...';
  uploadSocialMedia(file, 'post').then(function (media) {
    $('feedstatus').textContent = 'Publishing post...';
    return api('POST', '/posts', { caption: caption, mediaId: media.id });
  }).then(function () {
    $('imagefile').value = '';
    $('caption').value = '';
    $('feedstatus').textContent = 'Posted!';
    loadPosts();
  }).catch(function (err) {
    $('feedstatus').textContent = err.message || 'Could not publish media.';
  }).then(function () { $('publishbtn').disabled = false; });
});

function uploadSocialMedia(file, scope, recipient) {
  return new Promise(function (resolve, reject) {
    var endpoint = API + '/social/media?scope=' + encodeURIComponent(scope) +
      '&name=' + encodeURIComponent(file.name || 'attachment');
    if (recipient) endpoint += '&to=' + encodeURIComponent(recipient);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', endpoint);
    xhr.setRequestHeader('Authorization', 'Bearer ' + token);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.upload.onprogress = function (event) {
      if (event.lengthComputable) {
        var pct = Math.round(event.loaded / event.total * 100);
        var status = $('feedstatus');
        if (scope === 'post' && status) status.textContent = 'Uploading media... ' + pct + '%';
      }
    };
    xhr.onload = function () {
      var data = {};
      try { data = JSON.parse(xhr.responseText); } catch (e) {}
      if (xhr.status >= 200 && xhr.status < 300 && data.media && data.media.id) resolve(data.media);
      else reject(new Error(data.error || 'Media upload failed (HTTP ' + xhr.status + ').'));
    };
    xhr.onerror = function () { reject(new Error('Network error while uploading media.')); };
    xhr.send(file);
  });
}

var MEDIA_LIMITS = {
  image: 5 * 1048576,
  audio: 5 * 1048576,
  video: 7.5 * 1073741824,
  zip: 750 * 1048576
};

function formatLimit(n) {
  return n >= 1073741824 ? (n / 1073741824) + ' GB' : (n / 1048576) + ' MB';
}

function checkMediaFile(file, allowZip) {
  var kind = mediaKindFromFile(file);
  if (!kind) return 'Unsupported file type.';
  if (kind === 'zip' && !allowZip) return 'ZIP files can only be sent in DMs and announcements.';
  if (file.size > MEDIA_LIMITS[kind]) {
    return (kind === 'video' ? 'MP4' : kind === 'audio' ? 'MP3/audio' : kind === 'zip' ? 'ZIP' : 'Image') +
      ' files must be ' + formatLimit(MEDIA_LIMITS[kind]) + ' or smaller.';
  }
  return '';
}

function mediaKindFromFile(file) {
  var name = String(file.name || '').toLowerCase();
  var type = String(file.type || '').toLowerCase();
  if (type === 'application/zip' || type === 'application/x-zip-compressed' ||
      name.slice(-4) === '.zip') return 'zip';
  if (type.indexOf('video/') === 0 || /\.mp4$/.test(name)) return 'video';
  if (type.indexOf('audio/') === 0 || /\.(mp3|wav|ogg|m4a)$/.test(name)) return 'audio';
  if (type.indexOf('image/') === 0 || /\.(jpe?g|png|gif|webp)$/.test(name)) return 'image';
  return null;
}

function readFile(file) {
  return new Promise(function (resolve, reject) {
    var reader = new FileReader();

    reader.onload = function () {
      var dataUrl = String(reader.result);
      var comma = dataUrl.indexOf(',');

      if (comma < 0) {
        reject(new Error('Could not read that image.'));
        return;
      }

      resolve(dataUrl.slice(comma + 1));
    };

    reader.onerror = function () {
      reject(new Error('Could not read that image.'));
    };

    reader.readAsDataURL(file);
  });
}

function applyDarkMode(enabled) {
  document.body.classList.toggle('dark-mode', !!enabled);
}

function loadProfile(id) {
  api('GET', '/profiles/' + encodeURIComponent(id)).then(function (data) {
    if (data.profile.isMe) applyDarkMode(!!data.profile.darkMode);
    renderProfile(data.profile);
    renderPostList($('profposts'), data.posts,
      data.profile.isMe
        ? 'You have not posted anything yet.'
        : 'No posts yet.');
  }).catch(function (err) {
    $('profilecard').textContent = 'Could not load profile: ' + err.message;
    $('profposts').innerHTML = '';
  });
}

var presenceRef = null;

function paintPresence(online, invisible) {
  var r = presenceRef;
  if (!r) return;

  r.ring.className = r.baseClass + ' ring' + (online ? ' ring-on' : '');
  r.label.className = 'presence' + (online ? ' on' : '');

  if (online) {
    r.label.textContent = '\\u25CF Online';
  } else if (invisible) {
    r.label.textContent = '\\u25CF Offline (Invisible mode: you appear offline to others)';
  } else {
    r.label.textContent = '\\u25CF Offline';
  }
}

function renderProfile(p) {
  $('profilecol').style.background = p.bgColor;

  var box = $('profilecard');
  box.innerHTML = '';

  var card = el('div', 'profilecard');

  var top = el('div', 'profiletop');
  var av = avatar(p, 90);
  var presenceEl = el('div', 'presence');
  presenceRef = {
    userId: p.userId,
    isMe: p.isMe,
    ring: av,
    baseClass: av.className,
    label: presenceEl
  };
  paintPresence(p.online, p.isMe && p.invisible);
  top.appendChild(av);

  var info = el('div');
  info.appendChild(el('h2', null, p.displayName));
  info.appendChild(el('div', 'muted', '@' + p.username + ' (' + p.userId + ')'));
  info.appendChild(presenceEl);
  top.appendChild(info);
  card.appendChild(top);

  if (p.bio) card.appendChild(el('div', 'bio', p.bio));

  card.appendChild(el('div', 'stats',
    p.postCount + ' posts   ' + p.followersCount + ' followers   ' +
    p.followingCount + ' following   ' + p.friendsCount +
    (p.friendsCount === 1 ? ' friend' : ' friends')));

  var btns = el('div', 'profbtns');

  if (p.isMe) {
    var editBtn = el('button', null, 'Edit profile');
    btns.appendChild(editBtn);
    card.appendChild(btns);

    var editBox = buildEditor(p);
    editBox.style.display = 'none';
    card.appendChild(editBox);

    editBtn.onclick = function () {
      editBox.style.display = editBox.style.display === 'none' ? 'block' : 'none';
    };
  } else {
    var followBtn = el('button', p.isFollowing ? 'grey' : '',
      p.isFollowing ? 'Unfollow' : 'Follow');
    followBtn.onclick = function () {
      followBtn.disabled = true;
      api('POST', '/users/' + encodeURIComponent(p.userId) +
        (p.isFollowing ? '/unfollow' : '/follow')).then(function () {
        loadProfile(p.userId);
      }).catch(function (e) {
        alert(e.message);
        followBtn.disabled = false;
      });
    };

    var msgBtn = el('button', 'grey', 'Message');
    msgBtn.onclick = function () {
      showPage('messages');
      openChat({
        userId: p.userId,
        username: p.username,
        displayName: p.displayName
      });
    };

    btns.appendChild(followBtn);
    btns.appendChild(msgBtn);

    var friendBtn = function (label, cls, action, confirmText) {
      var b = el('button', cls, label);
      b.onclick = function () {
        if (confirmText && !confirm(confirmText)) return;
        b.disabled = true;
        api('POST', '/friends/' + action + '/' + encodeURIComponent(p.userId))
          .then(function () { loadProfile(p.userId); })
          .catch(function (e) { alert(e.message); b.disabled = false; });
      };
      return b;
    };

    if (p.friendStatus === 'friends') {
      card.appendChild(el('div', 'muted', 'You are friends with ' + p.displayName));
      btns.appendChild(friendBtn('Unfriend', 'grey', 'remove',
        'Remove ' + p.displayName + ' from your friends?'));
    } else if (p.friendStatus === 'outgoing') {
      card.appendChild(el('div', 'muted', 'Friend request sent - waiting for ' + p.displayName));
      btns.appendChild(friendBtn('Cancel request', 'grey', 'cancel'));
    } else if (p.friendStatus === 'incoming') {
      card.appendChild(el('div', 'muted', p.displayName + ' sent you a friend request'));
      btns.appendChild(friendBtn('Accept', '', 'accept'));
      btns.appendChild(friendBtn('Decline', 'grey', 'decline'));
    } else {
      btns.appendChild(friendBtn('Add friend', '', 'request'));
    }

    card.appendChild(btns);
  }

  if (me && me.isAdmin) {
    var histBtn = el('button', 'grey', 'View account history');
    histBtn.onclick = function () { openHistory(p); };
    btns.appendChild(histBtn);
  }

  box.appendChild(card);
}

function personText(u) {
  return u.displayName + ' (@' + (u.username || '?') + ', ' + u.userId + ')';
}

function histSection(box, title, count, headers, rows) {
  var sec = el('div', 'histsec');
  sec.appendChild(el('h4', null, title + ' (' + count + ')'));

  if (!rows.length) {
    sec.appendChild(el('div', 'histempty', 'Nothing here.'));
    box.appendChild(sec);
    return;
  }

  var scroll = el('div', 'histscroll');
  var table = el('table', 'hist');
  var headRow = document.createElement('tr');

  headers.forEach(function (h) { headRow.appendChild(el('th', null, h)); });
  table.appendChild(headRow);

  rows.forEach(function (cells) {
    var tr = document.createElement('tr');
    cells.forEach(function (c) { tr.appendChild(el('td', null, c)); });
    table.appendChild(tr);
  });

  scroll.appendChild(table);
  sec.appendChild(scroll);

  if (count > rows.length) {
    sec.appendChild(el('div', 'histempty', 'Showing the newest ' + rows.length + ' of ' + count + '.'));
  }

  box.appendChild(sec);
}

function openHistory(p) {
  $('histtitle').textContent = 'Account history: ' + p.displayName;
  $('histsub').textContent = '@' + p.username + ' (' + p.userId + ')';
  $('histbody').innerHTML = '';
  $('histbody').appendChild(el('div', 'empty', 'Loading...'));
  showModal('histmodal');

  api('GET', '/admin/users/' + encodeURIComponent(p.userId) + '/history').then(function (h) {
    var box = $('histbody');
    box.innerHTML = '';

    histSection(box, 'Inbox received', h.counts.inbox,
      ['Time', 'From', 'What', 'Read'],
      h.inbox.map(function (n) {
        var what = 'Followed them';
        if (n.type === 'friend_request') what = 'Sent a friend request';
        else if (n.type === 'friend_accepted') what = 'Accepted their friend request';
        else if (n.type === 'like') what = 'Liked their post';
        else if (n.type === 'comment') what = 'Commented: ' + (n.text || '');
        else if (n.type === 'post_deleted') what = 'Moderation notice: ' + (n.reason || n.text || '');
        return [formatTime(n.ts), personText(n.from), what, n.read ? 'Yes' : 'No'];
      }));

    histSection(box, 'Files downloaded', h.counts.downloads,
      ['Time', 'File', 'Bundle ID', 'Status'],
      h.downloads.map(function (d) {
        return [formatTime(d.ts), d.name + ' v' + d.version, d.bundleId,
          d.stillAvailable ? 'Available' : 'Deleted'];
      }));

    histSection(box, 'Files uploaded', h.counts.uploads,
      ['Time', 'File', 'Bundle ID', 'Size', 'Status'],
      h.uploads.map(function (u) {
        return [formatTime(u.ts), u.name + ' v' + u.version, u.bundleId,
          formatSize(u.size), u.stillAvailable ? 'Available' : 'Deleted'];
      }));

    histSection(box, 'DM transfers', h.counts.dms,
      ['Time sent', 'From', 'To', 'Type', 'Status'],
      h.dms.map(function (m) {
        var st = m.readAt ? 'Read ' + formatTime(m.readAt)
          : (m.deliveredAt ? 'Delivered' : 'Sent');
        return [formatTime(m.ts), m.from.userId + ' (' + m.from.displayName + ')',
          m.to.userId + ' (' + m.to.displayName + ')', m.type, st];
      }));

    box.appendChild(el('div', 'histempty',
      'DM entries show only who sent a message to whom and when. Message text is not shown.'));
  }).catch(function (err) {
    $('histbody').innerHTML = '';
    $('histbody').appendChild(el('div', 'empty', 'Could not load history: ' + err.message));
  });
}

function buildEditor(p) {
  var box = el('div', 'editbox');

  function field(labelText, node) {
    box.appendChild(el('label', null, labelText));
    box.appendChild(node);
  }

  var nameIn = document.createElement('input');
  nameIn.value = p.displayName;
  nameIn.maxLength = 40;
  field('Display name', nameIn);

  var userIn = document.createElement('input');
  userIn.value = p.username;
  userIn.maxLength = 20;
  field('Username (letters, numbers, underscore)', userIn);

  var bioIn = document.createElement('textarea');
  bioIn.value = p.bio;
  bioIn.maxLength = 300;
  field('Bio (300 characters max)', bioIn);

  var colorIn = document.createElement('input');
  colorIn.type = 'color';
  colorIn.value = p.bgColor;
  field('Profile background color', colorIn);

  var invRow = document.createElement('label');
  invRow.style.display = 'flex';
  invRow.style.alignItems = 'center';
  invRow.style.gap = '8px';
  invRow.style.color = '#1c1e21';
  invRow.style.fontSize = '14px';

  var invIn = document.createElement('input');
  invIn.type = 'checkbox';
  invIn.style.width = 'auto';
  invIn.checked = !!p.invisible;

  invRow.appendChild(invIn);
  invRow.appendChild(document.createTextNode(
    'Invisible (appear offline to everyone, even when you are online)'));
  box.appendChild(invRow);

  var darkRow = document.createElement('label');
  darkRow.style.display = 'flex';
  darkRow.style.alignItems = 'center';
  darkRow.style.gap = '8px';
  darkRow.style.color = '#1c1e21';
  darkRow.style.fontSize = '14px';
  darkRow.style.marginTop = '10px';
  var darkIn = document.createElement('input');
  darkIn.type = 'checkbox';
  darkIn.style.width = 'auto';
  darkIn.checked = !!p.darkMode;
  darkRow.appendChild(darkIn);
  darkRow.appendChild(document.createTextNode('Dark mode (black backgrounds and white text)'));
  box.appendChild(darkRow);

  var fileIn = document.createElement('input');
  fileIn.type = 'file';
  fileIn.accept = 'image/jpeg,image/png,image/gif,image/webp';
  field('Profile picture', fileIn);

  var status = el('div', 'editstatus');

  var row = el('div', 'profbtns');
  row.style.marginTop = '14px';

  var saveBtn = el('button', null, 'Save changes');
  var removeBtn = el('button', 'grey', 'Remove picture');
  row.appendChild(saveBtn);
  row.appendChild(removeBtn);
  box.appendChild(row);
  box.appendChild(status);

  fileIn.onchange = function () {
    var file = fileIn.files[0];
    if (!file) return;

    if (file.size > 5 * 1024 * 1024) {
      status.textContent = 'Images must be 5 MB or smaller.';
      return;
    }

    status.textContent = 'Uploading picture...';

    readFile(file).then(function (b64) {
      return api('POST', '/profile/avatar', {
        mimeType: file.type,
        imageData: b64
      });
    }).then(function () {
      loadProfile(me.userId);
    }).catch(function (e) {
      status.textContent = e.message;
    });
  };

  removeBtn.onclick = function () {
    api('POST', '/profile/avatar', { remove: true }).then(function () {
      loadProfile(me.userId);
    }).catch(function (e) {
      status.textContent = e.message;
    });
  };

  saveBtn.onclick = function () {
    saveBtn.disabled = true;
    status.textContent = 'Saving...';

    api('POST', '/profile', {
      displayName: nameIn.value,
      username: userIn.value.trim(),
      bio: bioIn.value,
      bgColor: colorIn.value,
      invisible: invIn.checked,
      darkMode: darkIn.checked
    }).then(function (d) {
      applyDarkMode(!!d.profile.darkMode);
      me.displayName = d.profile.displayName;
      me.username = d.profile.username;
      $('myname').textContent = me.displayName;
      loadProfile(me.userId);
    }).catch(function (e) {
      status.textContent = e.message;
      saveBtn.disabled = false;
    });
  };

  return box;
}

function setBadge(n) {
  $('profileTab').textContent = n > 0 ? 'Profile (' + n + ')' : 'Profile';
}

function refreshBadge() {
  api('GET', '/notifications/count').then(function (d) {
    setBadge(d.unread);
  }).catch(function () {});
}

function loadInbox() {
  api('GET', '/notifications').then(function (data) {
    var box = $('inboxlist');
    box.innerHTML = '';

    if (!data.notifications.length) {
      box.appendChild(el('div', 'empty',
        'No notifications yet. Likes, comments and follows will show up here.'));
    }

    data.notifications.forEach(function (n) {
      var row = el('div', 'notif' + (n.read ? '' : ' unread'));
      row.appendChild(avatar(n.from, 36));

      var text = el('div', 'ntext');

      if (n.type === 'post_deleted') {
        text.appendChild(document.createTextNode('Moderation notice: ' + (n.text || ('Your post was deleted. Reason: ' + (n.reason || 'Not specified')))));
      } else {
        var who = el('button', 'linklike',
          '@' + n.from.username + ' (' + n.from.userId + ')');
        who.onclick = function () { openProfile(n.from.userId); };
        text.appendChild(who);

        var what = ' started following you';
        if (n.type === 'like') what = ' liked your post';
        if (n.type === 'comment') what = ' commented on your post: ' + (n.text || '');
        if (n.type === 'friend_request') what = ' sent you a friend request';
        if (n.type === 'friend_accepted') what = ' accepted your friend request';

        text.appendChild(document.createTextNode(what));
      }
      text.appendChild(el('small', null, formatTime(n.ts)));

      if (n.type === 'friend_request' && n.requestPending) {
        var fbtns = el('div', 'profbtns');
        fbtns.style.marginTop = '6px';

        var answer = function (label, cls, action) {
          var b = el('button', cls, label);
          b.onclick = function (event) {
            event.stopPropagation();
            fbtns.querySelectorAll('button').forEach(function (x) { x.disabled = true; });
            api('POST', '/friends/' + action + '/' + encodeURIComponent(n.from.userId))
              .then(function () {
                loadInbox();
                if (presenceRef && presenceRef.userId === n.from.userId) loadProfile(n.from.userId);
              })
              .catch(function (e) {
                alert(e.message);
                loadInbox();
              });
          };
          return b;
        };

        fbtns.appendChild(answer('Accept', '', 'accept'));
        fbtns.appendChild(answer('Deny', 'grey', 'decline'));
        text.appendChild(fbtns);
      }

      if (n.type === 'friend_request' || n.type === 'friend_accepted') {
        row.style.cursor = 'pointer';
        row.onclick = function (event) {
          if (event.target.tagName === 'BUTTON') return;
          openProfile(n.from.userId);
        };
      }

      row.appendChild(text);

      if (n.postImageUrl) {
        var thumb = document.createElement('img');
        thumb.className = 'thumb';
        thumb.src = API + n.postImageUrl;
        thumb.alt = '';
        row.appendChild(thumb);
      }

      box.appendChild(row);
    });

    if (data.unread > 0 && currentPage === 'profile') {
      api('POST', '/notifications/read', {}).then(function () {
        setBadge(0);
      }).catch(function () {});
    } else {
      setBadge(data.unread);
    }
  }).catch(function (err) {
    $('inboxlist').textContent = 'Could not load inbox: ' + err.message;
  });
}

function markAllRead() {
  api('POST', '/notifications/read', {}).then(function () {
    setBadge(0);
    loadInbox();
  }).catch(function (e) {
    alert(e.message);
  });
}

var newsEditing = null;
var newsAttach = [];
var savedRange = null;

function loadNews() {
  api('GET', '/news').then(function (data) {
    renderNews(data.news);
  }).catch(function (err) {
    $('newslist').textContent = 'Could not load news: ' + err.message;
  });
}

function mediaSrc(media) {
  return API + media.url + '?token=' + encodeURIComponent(token);
}

function renderNews(items) {
  var admin = !!(me && me.isAdmin);
  var bar = $('newsbar');
  bar.innerHTML = '';

  if (admin) {
    var addBtn = el('button', null, 'New Announcement');
    addBtn.onclick = function () { openNewsEditor(null); };
    bar.appendChild(addBtn);
  } else {
    bar.appendChild(el('h2', null, 'iLegacy News'));
  }

  var list = $('newslist');
  list.innerHTML = '';

  if (!items.length) {
    list.appendChild(el('div', 'empty', 'No announcements yet.'));
    return;
  }

  items.forEach(function (item) {
    list.appendChild(renderNewsItem(item, admin));
  });
}

function renderNewsItem(item, admin) {
  var card = el('article', 'newscard');

  var head = el('div', 'newshead');
  head.appendChild(el('h3', null, item.title));
  head.appendChild(el('small', null, 'Posted by ' + item.author.displayName + ' - ' +
    formatTime(item.ts) + (item.editedAt ? ' (edited ' + formatTime(item.editedAt) + ')' : '')));
  card.appendChild(head);

  if (item.html) {
    var body = el('div', 'newsbody');
    body.innerHTML = item.html;
    card.appendChild(body);
  }

  if (item.media.length) {
    var box = el('div', 'newsmedia');

    item.media.forEach(function (media) {
      var src = mediaSrc(media);

      if (media.kind === 'image') {
        var img = document.createElement('img');
        img.src = src;
        img.alt = media.name;
        img.loading = 'lazy';
        img.onclick = function () { window.open(src, '_blank', 'noopener'); };
        box.appendChild(img);
      } else if (media.kind === 'audio') {
        var wrap = el('div');
        wrap.appendChild(el('span', 'mname', media.name));
        var audio = document.createElement('audio');
        audio.controls = true;
        audio.preload = 'metadata';
        audio.src = src;
        wrap.appendChild(audio);
        box.appendChild(wrap);
      } else if (media.kind === 'zip') {
        var zlink = el('a', 'filelink', '📦 ' + media.name + ' (' + formatSize(media.size) + ')');
        zlink.href = src;
        zlink.setAttribute('download', media.name);
        box.appendChild(zlink);
      } else {
        var video = document.createElement('video');
        video.controls = true;
        video.preload = 'metadata';
        video.setAttribute('playsinline', '');
        video.src = src;
        box.appendChild(video);
      }
    });

    card.appendChild(box);
  }

  if (admin) {
    var foot = el('div', 'newsfoot');
    var edit = el('button', 'act', 'Edit');
    edit.onclick = function () { openNewsEditor(item); };
    var del = el('button', 'act', 'Delete');
    del.onclick = function () {
      if (!confirm('Delete "' + item.title + '"? This cannot be undone.')) return;
      api('POST', '/news/' + encodeURIComponent(item.id) + '/delete')
        .then(loadNews)
        .catch(function (err) { alert(err.message); });
    };
    foot.appendChild(edit);
    foot.appendChild(del);
    card.appendChild(foot);
  }

  return card;
}

function openNewsEditor(item) {
  newsEditing = item;
  $('newsmodaltitle').textContent = item ? 'Edit Announcement' : 'New Announcement';
  $('ntitle').value = item ? item.title : '';
  $('neditor').innerHTML = item ? item.html : '';
  $('nfiles').value = '';
  $('nstatus').textContent = '';
  $('npublish').disabled = false;
  $('npublish').textContent = item ? 'Save changes' : 'Publish';

  newsAttach = item ? item.media.map(function (m) {
    return { id: m.id, name: m.name, kind: m.kind, size: m.size, state: 'done', pct: 100 };
  }) : [];

  renderAttachments();
  savedRange = null;
  showModal('newsmodal');
  $('ntitle').focus();
}

function renderAttachments() {
  var box = $('nattach');
  box.innerHTML = '';

  newsAttach.forEach(function (a) {
    var row = el('div', 'attach');
    row.appendChild(el('span', 'akind', a.kind === 'audio' ? 'SOUND' : a.kind.toUpperCase()));
    row.appendChild(el('span', 'aname', a.name + ' (' + formatSize(a.size) + ')'));

    var state = a.state === 'uploading' ? 'Uploading ' + a.pct + '%'
      : (a.state === 'error' ? a.error : 'Ready');
    var st = el('small', null, state);
    if (a.state === 'error') st.style.color = '#c0392b';
    row.appendChild(st);

    var rm = el('button', 'grey', 'Remove');
    rm.onclick = function () {
      newsAttach = newsAttach.filter(function (x) { return x !== a; });
      renderAttachments();
    };
    row.appendChild(rm);

    box.appendChild(row);
  });
}

function uploadNewsFile(file) {
  var a = { id: null, name: file.name, kind: 'file', size: file.size, state: 'uploading', pct: 0 };
  newsAttach.push(a);

  var fileProblem = checkMediaFile(file, true);
  if (fileProblem) {
    a.state = 'error';
    a.error = fileProblem;
    return;
  }

  var xhr = new XMLHttpRequest();
  xhr.open('POST', API + '/news/media?name=' + encodeURIComponent(file.name));
  xhr.setRequestHeader('Authorization', 'Bearer ' + token);
  xhr.setRequestHeader('Content-Type', 'application/octet-stream');

  xhr.upload.onprogress = function (event) {
    if (event.lengthComputable) {
      a.pct = Math.round(event.loaded / event.total * 100);
      renderAttachments();
    }
  };

  xhr.onload = function () {
    var data = {};
    try { data = JSON.parse(xhr.responseText); } catch (e) {}

    if (xhr.status >= 200 && xhr.status < 300 && data.media) {
      a.id = data.media.id;
      a.kind = data.media.kind;
      a.size = data.media.size;
      a.state = 'done';
      a.pct = 100;
    } else {
      a.state = 'error';
      a.error = data.error || 'Upload failed';
    }
    renderAttachments();
  };

  xhr.onerror = function () {
    a.state = 'error';
    a.error = 'Upload failed';
    renderAttachments();
  };

  xhr.send(file);
}

$('nfiles').addEventListener('change', function () {
  var files = Array.prototype.slice.call(this.files || []);

  files.forEach(function (file) {
    if (newsAttach.length >= 10) {
      $('nstatus').textContent = 'You can attach up to 10 files';
      return;
    }
    uploadNewsFile(file);
  });

  renderAttachments();
  this.value = '';
});

function publishNews() {
  var status = $('nstatus');
  status.textContent = '';

  var title = $('ntitle').value.trim();
  if (!title) { status.textContent = 'Enter a title'; return; }

  if (newsAttach.some(function (a) { return a.state === 'uploading'; })) {
    status.textContent = 'Wait for uploads to finish';
    return;
  }

  if (newsAttach.some(function (a) { return a.state === 'error'; })) {
    status.textContent = 'Remove the files that failed to upload';
    return;
  }

  var body = {
    title: title,
    html: $('neditor').innerHTML,
    mediaIds: newsAttach.map(function (a) { return a.id; })
  };

  var endpoint = newsEditing
    ? '/news/' + encodeURIComponent(newsEditing.id) + '/edit'
    : '/news';

  $('npublish').disabled = true;

  api('POST', endpoint, body).then(function () {
    hideModal('newsmodal');
    loadNews();
  }).catch(function (err) {
    $('npublish').disabled = false;
    status.textContent = err.message;
  });
}

document.addEventListener('selectionchange', function () {
  var sel = window.getSelection();
  var editor = $('neditor');

  if (sel.rangeCount && editor.contains(sel.anchorNode)) {
    savedRange = sel.getRangeAt(0).cloneRange();
  }
});

$('newstools').addEventListener('mousedown', function (event) {
  if (event.target.tagName === 'BUTTON') event.preventDefault();
});

$('neditor').addEventListener('paste', function (event) {
  event.preventDefault();
  var text = (event.clipboardData || window.clipboardData).getData('text/plain');
  document.execCommand('insertText', false, text);
});

function restoreSel() {
  var editor = $('neditor');
  editor.focus();

  if (savedRange) {
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(savedRange);
  }
}

function newsCmd(cmd, value) {
  restoreSel();
  document.execCommand('styleWithCSS', false, true);
  document.execCommand(cmd, false, value === undefined ? null : value);
}

function newsColor(cmd, value) {
  restoreSel();
  document.execCommand('styleWithCSS', false, true);

  if (cmd === 'hiliteColor') {
    if (!document.execCommand('hiliteColor', false, value)) {
      document.execCommand('backColor', false, value);
    }
  } else {
    document.execCommand(cmd, false, value);
  }
}

function newsFont(select) {
  if (select.value) newsCmd('fontName', select.value);
  select.value = '';
}

function newsSize(select) {
  var px = select.value;
  select.value = '';
  if (!px) return;

  restoreSel();
  document.execCommand('styleWithCSS', false, false);
  document.execCommand('fontSize', false, '7');

  var fonts = $('neditor').querySelectorAll('font[size="7"]');

  for (var i = 0; i < fonts.length; i++) {
    var f = fonts[i];
    var span = document.createElement('span');
    span.style.fontSize = px + 'px';

    while (f.firstChild) span.appendChild(f.firstChild);
    f.parentNode.replaceChild(span, f);
  }
}

function newsLink() {
  var url = prompt('Link address (must start with http:// or https://):', 'https://');
  if (!url) return;

  if (!/^https?:[/][/]/i.test(url)) {
    alert('The link must start with http:// or https://');
    return;
  }

  newsCmd('createLink', url);
}

var dlData = [];
var dlTags = [];
var editingDeb = null;

function tagClass(tag) {
  return 'tag-' + String(tag).toLowerCase().split(' ').join('-');
}

function showModal(id) {
  $(id).style.display = 'flex';
}

function hideModal(id) {
  $(id).style.display = 'none';
}

function formatSize(bytes) {
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
  if (bytes >= 1024) return Math.round(bytes / 1024) + ' KB';
  return bytes + ' B';
}

function loadDownloads() {
  api('GET', '/downloads').then(function (data) {
    dlData = data.categories;
    dlTags = data.tags || [];
    renderDownloads();
  }).catch(function (err) {
    $('dllist').textContent = 'Could not load downloads: ' + err.message;
  });
}

function renderDownloads() {
  var admin = !!(me && me.isAdmin);
  var bar = $('dlbar');
  bar.innerHTML = '';

  if (admin) {
    var addBtn = el('button', null, 'Add Category');
    addBtn.onclick = openCategoryModal;
    var upBtn = el('button', null, 'Upload .deb / .exe');
    upBtn.onclick = function () { openUploadModal(null); };
    bar.appendChild(addBtn);
    bar.appendChild(upBtn);
  } else {
    bar.appendChild(el('h2', null, 'Downloads'));
  }

  var list = $('dllist');
  list.innerHTML = '';

  if (!dlData.length) {
    list.appendChild(el('div', 'empty',
      admin ? 'No categories yet. Press Add Category to make one.'
            : 'Nothing has been added to Downloads yet.'));
    return;
  }

  dlData.forEach(function (category) {
    var box = el('section', 'dlcat');

    var head = el('div', 'dlcathead');
    var title = el('span', null, category.name);
    title.appendChild(el('small', null,
      category.debs.length + (category.debs.length === 1 ? ' file' : ' files')));
    head.appendChild(title);

    if (admin) {
      var delCat = el('button', 'act', 'Delete category');
      delCat.onclick = function () {
        if (!confirm('Delete "' + category.name + '" and all ' +
            category.debs.length + ' file(s) in it? This cannot be undone.')) return;
        api('POST', '/downloads/categories/' + encodeURIComponent(category.id) + '/delete')
          .then(loadDownloads)
          .catch(function (err) { alert(err.message); });
      };
      head.appendChild(delCat);
    }

    box.appendChild(head);

    var row = el('div', 'dlrow');

    if (!category.debs.length) {
      row.appendChild(el('div', 'muted', 'No files in this category yet.'));
    }

    category.debs.forEach(function (deb, index) {
      row.appendChild(renderDeb(deb, admin, index === 0));
    });

    box.appendChild(row);
    list.appendChild(box);
  });
}

function renderDeb(deb, admin, isNewest) {
  var card = el('div', 'dlcard');

  var title = el('div', 'dltitle', deb.name);
  title.appendChild(el('span', 'dlver', 'v' + deb.version));
  if (isNewest) title.appendChild(el('span', 'dlnew', 'NEWEST'));
  if (deb.tag) title.appendChild(el('span', 'dltag ' + tagClass(deb.tag), deb.tag.toUpperCase()));
  card.appendChild(title);

  card.appendChild(el('small', null, 'Author: ' + deb.author));
  card.appendChild(el('small', null, 'Bundle ID: ' + deb.bundleId));

  if (deb.minIOS || deb.maxIOS) {
    card.appendChild(el('small', null, 'iOS: ' + (deb.minIOS || 'any') +
      ' - ' + (deb.maxIOS || 'any')));
  }

  if (deb.description) card.appendChild(el('div', 'dldesc', deb.description));

  card.appendChild(el('small', null, formatSize(deb.size) + ' - ' +
    new Date(deb.uploadedAt).toLocaleDateString() + ' - ' +
    deb.downloads + (deb.downloads === 1 ? ' download' : ' downloads')));
  card.appendChild(el('small', null, 'Uploaded by ' + deb.uploadedBy));

  var btns = el('div', 'dlbtns');
  var dl = el('a', 'btnlink', 'Download');
  dl.href = API + '/downloads/debs/' + encodeURIComponent(deb.id) +
    '/file?token=' + encodeURIComponent(token);
  btns.appendChild(dl);

  if (admin) {
    var editDeb = el('button', 'act', 'Edit');
    editDeb.onclick = function () { openUploadModal(deb); };
    btns.appendChild(editDeb);

    var del = el('button', 'act', 'Delete');
    del.onclick = function () {
      if (!confirm('Delete ' + deb.name + ' v' + deb.version + '?')) return;
      api('POST', '/downloads/debs/' + encodeURIComponent(deb.id) + '/delete')
        .then(loadDownloads)
        .catch(function (err) { alert(err.message); });
    };
    btns.appendChild(del);
  }

  card.appendChild(btns);
  return card;
}

function openCategoryModal() {
  $('catname').value = '';
  $('caterr').textContent = '';
  showModal('catmodal');
  $('catname').focus();
}

function createCategory() {
  var name = $('catname').value.trim();
  $('caterr').textContent = '';

  if (!name) {
    $('caterr').textContent = 'Enter a category name';
    return;
  }

  $('catbtn').disabled = true;

  api('POST', '/downloads/categories', { name: name }).then(function () {
    $('catbtn').disabled = false;
    hideModal('catmodal');
    loadDownloads();
  }).catch(function (err) {
    $('catbtn').disabled = false;
    $('caterr').textContent = err.message;
  });
}

function openUploadModal(deb) {
  editingDeb = deb || null;
  if (!dlData.length) {
    alert('Add a category first.');
    return;
  }

  var select = $('upcat');
  select.innerHTML = '';

  dlData.forEach(function (category) {
    var option = document.createElement('option');
    option.value = category.id;
    option.textContent = category.name;
    select.appendChild(option);
  });

  ['upfile', 'upname', 'upauthor', 'upbundle', 'upversion', 'upmin', 'upmax', 'updesc']
    .forEach(function (id) { $(id).value = ''; });

  $('upstatus').style.color = '#c0392b';
  $('upstatus').textContent = '';
  $('upbtn').disabled = false;

  var tagSel = $('uptag');
  tagSel.innerHTML = '';
  var noTag = document.createElement('option');
  noTag.value = '';
  noTag.textContent = 'No tag';
  tagSel.appendChild(noTag);

  dlTags.forEach(function (t) {
    var option = document.createElement('option');
    option.value = t;
    option.textContent = t;
    tagSel.appendChild(option);
  });

  var editing = !!editingDeb;
  $('upmodaltitle').textContent = editing ? 'Edit file' : 'Upload .deb / .exe';
  $('upbtn').textContent = editing ? 'Save changes' : 'Upload';
  $('upfile').style.display = editing ? 'none' : '';
  $('upfilelabel').style.display = editing ? 'none' : '';

  if (editing) {
    select.value = editingDeb.categoryId;
    $('upname').value = editingDeb.name;
    $('upauthor').value = editingDeb.author;
    $('upbundle').value = editingDeb.bundleId;
    $('upversion').value = editingDeb.version;
    $('upmin').value = editingDeb.minIOS || '';
    $('upmax').value = editingDeb.maxIOS || '';
    $('updesc').value = editingDeb.description || '';
    tagSel.value = editingDeb.tag || '';
  }

  showModal('upmodal');
}

function saveDebEdit() {
  var status = $('upstatus');
  status.style.color = '#c0392b';
  status.textContent = '';

  var body = {
    categoryId: $('upcat').value,
    name: $('upname').value.trim(),
    author: $('upauthor').value.trim(),
    bundleId: $('upbundle').value.trim(),
    version: $('upversion').value.trim(),
    minIOS: $('upmin').value.trim(),
    maxIOS: $('upmax').value.trim(),
    description: $('updesc').value.trim(),
    tag: $('uptag').value
  };

  if (!body.name || !body.author || !body.bundleId || !body.version) {
    status.textContent = 'Name, author, bundle ID and version are required';
    return;
  }

  $('upbtn').disabled = true;

  api('POST', '/downloads/debs/' + encodeURIComponent(editingDeb.id) + '/edit', body)
    .then(function () {
      hideModal('upmodal');
      editingDeb = null;
      loadDownloads();
    }).catch(function (err) {
      $('upbtn').disabled = false;
      status.textContent = err.message;
    });
}

function uploadDeb() {
  if (editingDeb) { saveDebEdit(); return; }

  var file = $('upfile').files && $('upfile').files[0];
  var status = $('upstatus');
  status.style.color = '#c0392b';
  status.textContent = '';

  if (!file) { status.textContent = 'Choose a .deb or .exe file'; return; }
  if (!/[.](deb|exe)$/i.test(file.name)) { status.textContent = 'The file must end in .deb or .exe'; return; }
  if (file.size > 200 * 1024 * 1024) { status.textContent = 'Files must be 200 MB or smaller'; return; }

  var fields = {
    categoryId: $('upcat').value,
    name: $('upname').value.trim(),
    author: $('upauthor').value.trim(),
    bundleId: $('upbundle').value.trim(),
    version: $('upversion').value.trim(),
    minIOS: $('upmin').value.trim(),
    maxIOS: $('upmax').value.trim(),
    description: $('updesc').value.trim(),
    fileName: file.name,
    tag: $('uptag').value
  };

  if (!fields.name || !fields.author || !fields.bundleId || !fields.version) {
    status.textContent = 'Name, author, bundle ID and version are required';
    return;
  }

  var query = Object.keys(fields).map(function (key) {
    return key + '=' + encodeURIComponent(fields[key]);
  }).join('&');

  var xhr = new XMLHttpRequest();
  xhr.open('POST', API + '/downloads/debs?' + query);
  xhr.setRequestHeader('Authorization', 'Bearer ' + token);
  xhr.setRequestHeader('Content-Type', 'application/octet-stream');

  $('upbtn').disabled = true;
  status.style.color = '#65676b';
  status.textContent = 'Uploading... 0%';

  xhr.upload.onprogress = function (event) {
    if (event.lengthComputable) {
      status.textContent = 'Uploading... ' +
        Math.round(event.loaded / event.total * 100) + '%';
    }
  };

  xhr.onload = function () {
    var data = {};
    try { data = JSON.parse(xhr.responseText); } catch (e) {}

    if (xhr.status >= 200 && xhr.status < 300) {
      hideModal('upmodal');
      loadDownloads();
    } else {
      $('upbtn').disabled = false;
      status.style.color = '#c0392b';
      status.textContent = data.error || 'Upload failed';
    }
  };

  xhr.onerror = function () {
    $('upbtn').disabled = false;
    status.style.color = '#c0392b';
    status.textContent = 'Upload failed. Is the server reachable?';
  };

  xhr.send(file);
}

$('catname').addEventListener('keydown', function (event) {
  if (event.key === 'Enter') createCategory();
});

function loadConvos() {
  api('GET', '/conversations').then(function (data) {
    var box = $('convos');
    box.innerHTML = '';

    data.conversations.forEach(function (conversation) {
      var user = conversation.with;
      if (!user) return;

      var div = document.createElement('div');

      div.className =
        'convo' +
        (current && current.userId === user.userId ? ' active' : '');

      var name = document.createElement('b');
      name.textContent = user.displayName + ' (' + user.userId + ')';

      var last = document.createElement('small');
      last.textContent = conversation.last.type === 'image'
        ? '📷 Photo' + (conversation.last.text ? ': ' + conversation.last.text : '')
        : (conversation.last.type === 'media'
          ? ({image: '📷 Photo/GIF', audio: '🎵 Audio', video: '🎬 Video', zip: '📦 ZIP file'}[conversation.last.mediaKind] || 'Attachment') + (conversation.last.text ? ': ' + conversation.last.text : '')
          : (conversation.last.text || ''));

      div.appendChild(name);
      div.appendChild(last);

      div.onclick = function () {
        openChat(user);
      };

      box.appendChild(div);
    });
  }).catch(function (err) {
    console.error('Could not load conversations:', err.message);
  });
}

function newChat() {
  var id = $('newid').value.trim().toUpperCase();
  $('err2').textContent = '';

  if (!id) return;

  api('GET', '/users/' + encodeURIComponent(id)).then(function (data) {
    $('newid').value = '';
    showPage('messages');
    openChat(data.user);
  }).catch(function (err) {
    $('err2').textContent = err.message;
  });
}

function openChat(user) {
  current = user;
  shown = {};

  $('chatheadtext').textContent = user.displayName + ' (' + user.userId + ')';
  $('callbtn').style.display = '';
  $('callbtn').disabled = !!(callState || incomingCall);
  $('text').disabled = false;
  $('dmimage').disabled = false;
  $('sendbtn').disabled = false;
  $('msgs').innerHTML = '';

  api('GET', '/messages?with=' + encodeURIComponent(user.userId))
    .then(function (data) {
      data.messages.forEach(addMsg);

      if (!data.messages.length) {
        $('msgs').innerHTML =
          '<div class="empty">No messages yet. Say hi!</div>';
      }

      return api('POST', '/messages/read', { with: user.userId });
    })
    .then(function () {
      loadConvos();
    })
    .catch(function (err) {
      $('msgs').textContent = 'Could not load messages: ' + err.message;
    });

  loadConvos();
  $('text').focus();
}

function statusText(message) {
  if (message.from !== me.userId) return '';
  if (message.readAt) return '✓✓ Read';
  if (message.deliveredAt) return '✓✓ Delivered';
  return '✓ Sent';
}

function updateMessageStatus(status) {
  var bubble = document.querySelector('[data-message-id="' + status.id + '"]');
  if (!bubble) return;
  var label = bubble.querySelector('.msgstatus');
  if (!label) return;
  label.textContent = status.readAt ? '✓✓ Read' :
    (status.deliveredAt ? '✓✓ Delivered' : '✓ Sent');
  label.className = 'msgstatus' + (status.readAt ? ' read' : '');
}

function addMsg(message) {
  if (shown[message.id]) {
    updateMessageStatus(message);
    return;
  }

  shown[message.id] = true;

  var box = $('msgs');
  var empty = box.querySelector('.empty');
  if (empty) box.removeChild(empty);

  var div = document.createElement('div');
  div.className = 'msg ' + (message.from === me.userId ? 'mine' : 'theirs');
  div.setAttribute('data-message-id', message.id);

  if (message.type === 'media' && message.mediaId && message.mediaKind === 'zip') {
    var zipLink = el('a', 'filelink', '📦 ' + (message.mediaName || 'archive.zip') +
      (message.mediaSize ? ' (' + formatSize(message.mediaSize) + ')' : ''));
    zipLink.href = API + '/social/media/' + encodeURIComponent(message.mediaId) +
      '?token=' + encodeURIComponent(token);
    zipLink.setAttribute('download', message.mediaName || 'archive.zip');
    div.appendChild(zipLink);
  }

  if (message.type === 'media' && message.mediaId && message.mediaKind !== 'zip') {
    var mediaUrl = API + '/social/media/' + encodeURIComponent(message.mediaId) +
      '?token=' + encodeURIComponent(token);
    var mediaEl;
    if (message.mediaKind === 'video') {
      mediaEl = document.createElement('video');
      mediaEl.controls = true;
      mediaEl.playsInline = true;
      mediaEl.preload = 'metadata';
    } else if (message.mediaKind === 'audio') {
      mediaEl = document.createElement('audio');
      mediaEl.controls = true;
      mediaEl.preload = 'metadata';
    } else {
      mediaEl = document.createElement('img');
      mediaEl.alt = 'Photo or GIF attachment';
      mediaEl.onclick = function () { window.open(mediaUrl, '_blank', 'noopener'); };
    }
    mediaEl.className = 'socialmedia';
    mediaEl.src = mediaUrl;
    div.appendChild(mediaEl);
  }

  if (message.type === 'image' && message.filename) {
    var img = document.createElement('img');
    img.className = 'dmimg';
    img.alt = 'Image message';
    img.src = API + '/dm-uploads/' + encodeURIComponent(message.filename) +
      '?token=' + encodeURIComponent(token);
    img.onclick = function () {
      window.open(img.src, '_blank', 'noopener');
    };
    div.appendChild(img);
  }

  if (message.text) {
    var caption = document.createElement('div');
    caption.textContent = message.text;
    div.appendChild(caption);
  }

  var time = document.createElement('small');
  time.textContent = new Date(message.ts).toLocaleTimeString();
  div.appendChild(time);

  if (message.from === me.userId) {
    var status = document.createElement('span');
    status.className = 'msgstatus' + (message.readAt ? ' read' : '');
    status.textContent = statusText(message);
    div.appendChild(status);
  }

  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}

function sendMsg() {
  var input = $('text');
  var messageText = input.value.trim();
  var fileInput = $('dmimage');
  var file = fileInput.files && fileInput.files[0];
  if (!current || (!messageText && !file)) return;
  function sendPayload(payload) {
    api('POST', '/messages', payload).then(function (data) {
      input.value = '';
      fileInput.value = '';
      addMsg(data.message);
      loadConvos();
    }).catch(function (err) { alert(err.message); });
  }
  if (!file) { sendPayload({ to: current.userId, text: messageText }); return; }
  var fileProblem = checkMediaFile(file, true);
  if (fileProblem) { alert(fileProblem); return; }
  var sendButton = $('sendbtn');
  sendButton.disabled = true;
  uploadSocialMedia(file, 'dm', current.userId).then(function (media) {
    sendPayload({ to: current.userId, text: messageText, mediaId: media.id });
  }).catch(function (err) { alert(err.message || 'Media upload failed.'); })
    .then(function () { sendButton.disabled = false; });
}

function connectStream() {
  if (es) es.close();

  es = new EventSource(
    API + '/stream?token=' + encodeURIComponent(token)
  );

  es.addEventListener('call_invite', function (event) {
    handleCallInvite(JSON.parse(event.data));
  });

  es.addEventListener('call_signal', function (event) {
    handleCallSignal(JSON.parse(event.data));
  });

  es.addEventListener('call_accepted', function (event) {
    var data = JSON.parse(event.data);
    if (callState && callState.callId === data.callId) {
      stopCallTone();
      callPanel('iLegacy Calling', 'Answered — connecting audio…', { hangup: true });
    }
  });

  es.addEventListener('call_ended', function (event) {
    handleCallEnded(JSON.parse(event.data));
  });

  es.addEventListener('message', function (event) {
    var message = JSON.parse(event.data);

    if (
      current &&
      (message.from === current.userId || message.to === current.userId)
    ) {
      addMsg(message);

      if (message.from === current.userId && currentPage === 'messages') {
        api('POST', '/messages/read', { with: current.userId }).catch(function () {});
      }
    }

    loadConvos();
  });

  es.addEventListener('message_status', function (event) {
    updateMessageStatus(JSON.parse(event.data));
  });

  es.addEventListener('friend_update', function (event) {
    var d = JSON.parse(event.data);

    if (currentPage === 'profile' && presenceRef && !presenceRef.isMe &&
        presenceRef.userId === d.userId) {
      loadProfile(d.userId);
    }
  });

  es.addEventListener('presence', function (event) {
    var d = JSON.parse(event.data);

    if (currentPage === 'profile' && presenceRef && !presenceRef.isMe &&
        presenceRef.userId === d.userId) {
      paintPresence(d.online, false);
    }
  });

  es.addEventListener('notification', function () {
    if (currentPage === 'profile') {
      loadInbox();
    } else {
      refreshBadge();
    }
  });
}

$('text').addEventListener('keydown', function (event) {
  if (event.key === 'Enter') sendMsg();
});

$('dmimage').addEventListener('change', function () {
  if (this.files && this.files[0]) {
    var fileProblem = checkMediaFile(this.files[0], true);
    if (fileProblem) {
      alert(fileProblem);
      this.value = '';
    }
  }
});

$('p').addEventListener('keydown', function (event) {
  if (event.key === 'Enter') doAuth('login');
});

$('newid').addEventListener('keydown', function (event) {
  if (event.key === 'Enter') newChat();
});

if (token) {
  api('GET', '/me').then(function (data) {
    showApp(data.user);
  }).catch(function () {
    localStorage.removeItem('il_token');
    token = null;
  });
}
</script>
</body>
</html>`;

process.on('SIGINT', () => {
  log('INFO', 'Shutting down iLegacy...');
  saveDbImmediately();
  process.exit(0);
});

process.on('SIGTERM', () => {
  saveDbImmediately();
  process.exit(0);
});
