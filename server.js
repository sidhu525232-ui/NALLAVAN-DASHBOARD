'use strict';
// APPAVI KEY SERVER v2 — licence key generator + admin website. No npm packages needed (Node 18+).
//
//  Extension API (public):   POST /api/activate  {key, deviceId, info}
//                            POST /api/check     {key, deviceId}
//  Admin website:            GET  /              (login with ADMIN_PASSWORD)
//  Admin API (Bearer token): /admin/login, /admin/keys, /admin/generate, /admin/expire,
//                            /admin/restore, /admin/reset-device, /admin/delete,
//                            /admin/backup, /admin/import

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const LEASE_HOURS = Math.max(0.1, Number(process.env.LEASE_HOURS) || 6);
const REDIS_URL = (process.env.UPSTASH_REDIS_REST_URL || '').replace(/\/$/, '');
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';
const REDIS_KEY = 'appavi_key_db';
const DAY = 86400000;
const TYPES = { '7': 7, '15': 15, '30': 30, 'life': 0 };

// ── Signing key (ECDSA P-256). The extension only holds the PUBLIC half. ─────
function loadSigningKey() {
    let pem = '';
    if (process.env.SIGNING_KEY_B64) pem = Buffer.from(process.env.SIGNING_KEY_B64, 'base64').toString('utf8');
    else {
        const f = path.join(__dirname, 'signing-key.json');
        if (!fs.existsSync(f)) throw new Error('signing-key.json missing');
        pem = JSON.parse(fs.readFileSync(f, 'utf8')).privateKeyPem;
    }
    return crypto.createPrivateKey(pem);
}
const SIGN_KEY = loadSigningKey();
const SESSION_SECRET = crypto.createHash('sha256').update('appavi-session|' + ADMIN_PASSWORD + '|' + SIGN_KEY.export({ type: 'pkcs8', format: 'der' }).toString('base64')).digest();

// ── Storage: Upstash Redis (survives Render free plan) or a JSON file ────────
let db = { keys: {} };
let saveChain = Promise.resolve();
const DB_FILE = path.join(DATA_DIR, 'db.json');

async function redis(cmd, body) {
    const r = await fetch(REDIS_URL + cmd, { method: body === undefined ? 'GET' : 'POST', headers: { Authorization: 'Bearer ' + REDIS_TOKEN }, body });
    if (!r.ok) throw new Error('redis ' + r.status);
    return r.json();
}
async function loadDb() {
    try {
        if (REDIS_URL && REDIS_TOKEN) {
            const j = await redis('/get/' + REDIS_KEY);
            if (j && j.result) db = JSON.parse(j.result);
        } else if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    } catch (e) { console.error('[db] load failed:', e.message); }
    if (!db || typeof db !== 'object' || !db.keys) db = { keys: {} };
}
function saveDb() {
    const snapshot = JSON.stringify(db);
    saveChain = saveChain.then(async () => {
        try {
            if (REDIS_URL && REDIS_TOKEN) await redis('/set/' + REDIS_KEY, snapshot);
            else {
                fs.mkdirSync(DATA_DIR, { recursive: true });
                const tmp = DB_FILE + '.tmp';
                fs.writeFileSync(tmp, snapshot);
                fs.renameSync(tmp, DB_FILE);
            }
        } catch (e) { console.error('[db] save failed:', e.message); }
    });
    return saveChain;
}

// ── Helpers ──────────────────────────────────────────────────────────────────
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';     // 32 symbols, no 0/O/1/I
function newKey() {
    for (;;) {
        const b = crypto.randomBytes(12);
        let s = '';
        for (let i = 0; i < 12; i++) s += ALPHA[b[i] % 32];
        const k = 'NLV-' + s.match(/.{4}/g).join('-');
        if (!db.keys[k]) return k;
    }
}
const normKey = (k) => {
    const s = String(k || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (s.startsWith('NLV') && s.length === 15) return 'NLV-' + s.slice(3).match(/.{4}/g).join('-');
    return String(k || '').trim().toUpperCase();
};
const cleanDevice = (d) => (typeof d === 'string' && /^[A-Za-z0-9_-]{16,80}$/.test(d)) ? d : '';

function evalKey(rec, deviceId, now) {
    if (!rec) return { code: 'not_found', msg: 'Invalid key' };
    if (rec.revoked) return { code: 'revoked', msg: 'This key was expired by the admin' };
    if (rec.expiresAt && now >= rec.expiresAt) return { code: 'expired', msg: 'This key has expired' };
    if (rec.deviceId && rec.deviceId !== deviceId) return { code: 'device_mismatch', msg: 'This key is already used on another device' };
    return null;
}
function makeToken(rec, deviceId, now) {
    const ke = rec.expiresAt || 0;
    let le = now + LEASE_HOURS * 3600000;
    if (ke && ke < le) le = ke;
    const payload = b64u(JSON.stringify({ v: 1, t: rec.type, d: deviceId, ke, le, iat: now }));
    const sig = crypto.sign('sha256', Buffer.from(payload), { key: SIGN_KEY, dsaEncoding: 'ieee-p1363' });
    return payload + '.' + b64u(sig);
}
function okReply(rec, deviceId, now) {
    return { ok: true, token: makeToken(rec, deviceId, now), type: rec.type, expiresAt: rec.expiresAt || 0, serverTime: now };
}
function keyStatus(rec, now) {
    if (rec.revoked) return 'revoked';
    if (rec.expiresAt && now >= rec.expiresAt) return 'expired';
    return rec.deviceId ? 'active' : 'unused';
}

// ── Rate limiting (per IP, in memory) ────────────────────────────────────────
const buckets = new Map();
function limited(name, ip, max, windowMs) {
    const k = name + '|' + ip, now = Date.now();
    let b = buckets.get(k);
    if (!b || now > b.reset) { b = { n: 0, reset: now + windowMs }; buckets.set(k, b); }
    b.n++;
    return b.n > max;
}
setInterval(() => { const now = Date.now(); for (const [k, b] of buckets) if (now > b.reset) buckets.delete(k); }, 60000).unref();

// ── Admin session token ──────────────────────────────────────────────────────
function makeSession() {
    const exp = String(Date.now() + 12 * 3600000);
    return exp + '.' + crypto.createHmac('sha256', SESSION_SECRET).update(exp).digest('base64url');
}
function checkSession(tok) {
    if (!ADMIN_PASSWORD || typeof tok !== 'string') return false;
    const [exp, sig] = tok.split('.');
    if (!exp || !sig || Number(exp) < Date.now()) return false;
    const want = crypto.createHmac('sha256', SESSION_SECRET).update(exp).digest('base64url');
    const a = Buffer.from(sig), b = Buffer.from(want);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function passwordOk(p) {
    if (!ADMIN_PASSWORD || typeof p !== 'string') return false;
    const a = crypto.createHash('sha256').update(p).digest(), b = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest();
    return crypto.timingSafeEqual(a, b);
}

// ── HTTP plumbing ────────────────────────────────────────────────────────────
function send(res, code, obj, extra) {
    const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
    res.writeHead(code, Object.assign({
        'Content-Type': typeof obj === 'string' ? 'text/html; charset=utf-8' : 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
    }, extra || {}));
    res.end(body);
}
function readJson(req, limit) {
    return new Promise((resolve, reject) => {
        let size = 0; const chunks = [];
        req.on('data', (c) => { size += c.length; if (size > limit) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
        req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch (e) { reject(new Error('bad json')); } });
        req.on('error', reject);
    });
}
const clientIp = (req) => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

let INDEX_HTML = '';
try { INDEX_HTML = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8'); } catch (_) { INDEX_HTML = '<h1>public/index.html missing</h1>'; }

// ── Extension endpoints ──────────────────────────────────────────────────────
async function handleLicence(req, res, kind) {
    const ip = clientIp(req);
    if (limited('lic', ip, 120, 60000)) return send(res, 429, { ok: false, code: 'rate', msg: 'Too many requests, wait a minute' });
    let body;
    try { body = await readJson(req, 8192); } catch (_) { return send(res, 400, { ok: false, code: 'bad_request', msg: 'Bad request' }); }
    const key = normKey(body.key), deviceId = cleanDevice(body.deviceId), now = Date.now();
    if (!deviceId) return send(res, 400, { ok: false, code: 'bad_request', msg: 'Bad device id' });
    const rec = db.keys[key];
    const bad = evalKey(rec, deviceId, now);
    if (bad) {
        if (!rec && limited('badkey', ip, 20, 600000)) return send(res, 429, { ok: false, code: 'rate', msg: 'Too many wrong keys, try again in 10 minutes' });
        return send(res, 403, Object.assign({ ok: false }, bad));
    }
    if (kind === 'activate' && !rec.deviceId) {                     // first use: bind the device and start the timer
        rec.deviceId = deviceId;
        rec.activatedAt = now;
        const days = TYPES[rec.type];
        rec.expiresAt = days ? now + days * DAY : 0;
    } else if (kind === 'check' && !rec.deviceId) {
        return send(res, 403, { ok: false, code: 'not_activated', msg: 'Key not activated on this device' });
    }
    rec.lastSeenAt = now; rec.lastIp = ip;
    if (typeof body.info === 'string') rec.info = body.info.slice(0, 200);
    saveDb();
    return send(res, 200, okReply(rec, deviceId, now));
}

// ── Admin endpoints ──────────────────────────────────────────────────────────
async function handleAdmin(req, res, route) {
    const ip = clientIp(req);
    if (route === 'login') {
        if (!ADMIN_PASSWORD) return send(res, 503, { ok: false, msg: 'Set the ADMIN_PASSWORD environment variable on the server first' });
        if (limited('login', ip, 8, 600000)) return send(res, 429, { ok: false, msg: 'Too many attempts, wait 10 minutes' });
        let b; try { b = await readJson(req, 2048); } catch (_) { return send(res, 400, { ok: false, msg: 'Bad request' }); }
        if (!passwordOk(b.password)) return send(res, 401, { ok: false, msg: 'Wrong password' });
        return send(res, 200, { ok: true, token: makeSession() });
    }
    const auth = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!checkSession(auth)) return send(res, 401, { ok: false, msg: 'Login required' });
    const now = Date.now();

    if (route === 'keys') {
        const list = Object.values(db.keys).sort((a, b) => b.createdAt - a.createdAt).map((r) => Object.assign({}, r, { status: keyStatus(r, now) }));
        const stats = { total: list.length, unused: 0, active: 0, expired: 0, revoked: 0 };
        list.forEach((r) => { stats[r.status]++; });
        return send(res, 200, { ok: true, now, stats, keys: list });
    }
    if (route === 'backup') return send(res, 200, { ok: true, keys: db.keys });

    let b; try { b = await readJson(req, route === 'import' ? 20 * 1024 * 1024 : 8192); } catch (e) { return send(res, 400, { ok: false, msg: e.message }); }
    const rec = db.keys[normKey(b.key)];

    if (route === 'generate') {
        const type = String(b.type);
        if (!(type in TYPES)) return send(res, 400, { ok: false, msg: 'Type must be 7, 15, 30 or life' });
        const count = Math.min(200, Math.max(1, parseInt(b.count, 10) || 1));
        const note = String(b.note || '').slice(0, 80);
        const made = [];
        for (let i = 0; i < count; i++) {
            const k = newKey();
            db.keys[k] = { key: k, type, days: TYPES[type], createdAt: now, note, activatedAt: 0, expiresAt: 0, deviceId: '', info: '', lastSeenAt: 0, lastIp: '', revoked: false, revokedAt: 0 };
            made.push(k);
        }
        await saveDb();
        return send(res, 200, { ok: true, keys: made });
    }
    if (route === 'import') {
        if (!b.keys || typeof b.keys !== 'object') return send(res, 400, { ok: false, msg: 'Backup file is not valid' });
        let n = 0;
        for (const k of Object.keys(b.keys)) { const r = b.keys[k]; if (r && r.key === k && r.type in TYPES) { db.keys[k] = r; n++; } }
        await saveDb();
        return send(res, 200, { ok: true, imported: n });
    }
    if (!rec) return send(res, 404, { ok: false, msg: 'Key not found' });
    if (route === 'expire') { rec.revoked = true; rec.revokedAt = now; }
    else if (route === 'restore') { rec.revoked = false; rec.revokedAt = 0; }
    else if (route === 'reset-device') { rec.deviceId = ''; rec.info = ''; rec.lastIp = ''; if (rec.activatedAt && TYPES[rec.type] && rec.expiresAt > now) { /* keep the running timer */ } }
    else if (route === 'delete') delete db.keys[rec.key];
    else return send(res, 404, { ok: false, msg: 'Unknown action' });
    await saveDb();
    return send(res, 200, { ok: true });
}

// ── Router ───────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
    try {
        const url = new URL(req.url, 'http://x');
        const p = url.pathname.replace(/\/+$/, '') || '/';
        if (req.method === 'OPTIONS') return send(res, 204, '');
        if (p === '/' || p === '/admin') return send(res, 200, INDEX_HTML);
        if (p === '/api/ping') return send(res, 200, { ok: true, time: Date.now() });
        if (req.method === 'POST' && p === '/api/activate') return await handleLicence(req, res, 'activate');
        if (req.method === 'POST' && p === '/api/check') return await handleLicence(req, res, 'check');
        if (p.startsWith('/admin/')) return await handleAdmin(req, res, p.slice(7));
        return send(res, 404, { ok: false, msg: 'Not found' });
    } catch (e) {
        console.error('[server]', e);
        try { send(res, 500, { ok: false, msg: 'Server error' }); } catch (_) {}
    }
});

loadDb().then(() => {
    server.listen(PORT, () => {
        console.log('APPAVI key server on :' + PORT + ' — keys loaded: ' + Object.keys(db.keys).length + ' — storage: ' + (REDIS_URL ? 'Upstash Redis' : DB_FILE));
        if (!ADMIN_PASSWORD) console.warn('WARNING: ADMIN_PASSWORD is not set — the admin website cannot be used until you set it.');
    });
});
