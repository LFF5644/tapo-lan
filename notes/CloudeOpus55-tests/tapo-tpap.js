#!/usr/bin/env node
// Minimaler Tapo-TPAP-Client (SPAKE2+ / P-256) – ohne Abhängigkeiten, Node >= 18
// Funktioniert OHNE "Third-Party Compatibility". Portiert von raymondlo84/tapo-tpap-client (tpap_proto.py)
// Nutzung: TAPO_USER=mail TAPO_PASS=pw node tapo-tpap.js <ip> [on|off|info|<methode> [json]]
// Debug:   TAPO_DEBUG=1 ...
// ACHTUNG: Kein Auto-Retry beim Login – zu viele Fehlversuche sperren das Gerät vorübergehend.
'use strict';
const crypto = require('crypto');
const http = require('http');

const DEBUG = !!process.env.TAPO_DEBUG;
const dbg = (...a) => DEBUG && console.error('DEBUG', ...a);

// ---------- P-256 Arithmetik (BigInt, affin) ----------
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const A = P - 3n;
const ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const G = {
  x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
};
const mod = (a, m = P) => ((a % m) + m) % m;
const inv = a => { // erweiterter Euklid
  let [r0, r1, s0, s1] = [mod(a), P, 1n, 0n];
  while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  return mod(s0);
};
const add = (p, q) => {
  if (!p) return q; if (!q) return p;
  if (p.x === q.x && mod(p.y + q.y) === 0n) return null;
  const l = p.x === q.x
    ? mod((3n * p.x * p.x + A) * inv(2n * p.y))
    : mod((q.y - p.y) * inv(q.x - p.x));
  const x = mod(l * l - p.x - q.x);
  return { x, y: mod(l * (p.x - x) - p.y) };
};
const mul = (k, p) => {
  let r = null; k = mod(k, ORDER);
  for (; k > 0n; k >>= 1n, p = add(p, p)) if (k & 1n) r = add(r, p);
  return r;
};
const neg = p => ({ x: p.x, y: mod(-p.y) });

const b2n = b => BigInt('0x' + (b.toString('hex') || '0'));
const n2b = (n, len) => Buffer.from(n.toString(16).padStart(len * 2, '0'), 'hex');
const decode = buf => { // SEC1 komprimiert/unkomprimiert -> Punkt
  const u = crypto.ECDH.convertKey(buf, 'prime256v1', undefined, undefined, 'uncompressed');
  return { x: b2n(u.subarray(1, 33)), y: b2n(u.subarray(33, 65)) };
};
const encode = p => Buffer.concat([Buffer.from([4]), n2b(p.x, 32), n2b(p.y, 32)]);

const M = decode(Buffer.from('02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f', 'hex'));
const N = decode(Buffer.from('03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49', 'hex'));

// ---------- Krypto-Helfer ----------
const hash = (alg, d) => crypto.createHash(alg).update(d).digest();
const hex = (alg, s) => crypto.createHash(alg).update(s).digest('hex');
const hkdf = (alg, ikm, salt, info, len) => Buffer.from(crypto.hkdfSync(alg, ikm, salt, info, len));
const l8 = b => { const h = Buffer.alloc(8); h.writeBigUInt64LE(BigInt(b.length)); return Buffer.concat([h, b]); };
const encodeW = w => {
  let u = w === 0n ? Buffer.from([0]) : Buffer.from(w.toString(16).padStart(Math.ceil(w.toString(16).length / 2) * 2, '0'), 'hex');
  return (u.length % 2 && u[0] & 0x80) ? Buffer.concat([Buffer.from([0]), u]) : u;
};
const cmac = (key, msg) => { // AES-CMAC (RFC 4493), nur für cipher_suites 8/9
  const alg = `aes-${key.length * 8}-ecb`;
  const enc = b => { const c = crypto.createCipheriv(alg, key, null); c.setAutoPadding(false); return Buffer.concat([c.update(b), c.final()]); };
  const dbl = b => { const o = Buffer.alloc(16); for (let i = 0; i < 16; i++) o[i] = (b[i] << 1) | (i < 15 ? b[i + 1] >> 7 : 0); if (b[0] & 0x80) o[15] ^= 0x87; return o; };
  const k1 = dbl(enc(Buffer.alloc(16))), k2 = dbl(k1);
  const n = Math.max(1, Math.ceil(msg.length / 16)), full = msg.length && msg.length % 16 === 0;
  const last = Buffer.alloc(16); msg.copy(last, 0, (n - 1) * 16);
  if (!full) last[msg.length - (n - 1) * 16] = 0x80;
  let x = Buffer.alloc(16);
  for (let i = 0; i < n - 1; i++) x = enc(xor(x, msg.subarray(i * 16, i * 16 + 16)));
  return enc(xor(x, xor(last, full ? k1 : k2)));
};
const xor = (a, b) => Buffer.from(a.map((v, i) => v ^ b[i]));

const CIPHERS = {
  aes_128_ccm: { node: 'aes-128-ccm', tag: 'aes128', kl: 16 },
  aes_256_ccm: { node: 'aes-256-ccm', tag: 'aes256', kl: 32 },
  chacha20_poly1305: { node: 'chacha20-poly1305', tag: 'chacha20', kl: 32 },
};

function buildCred(extra, user, pw, mac12) {
  if (!extra || !Object.keys(extra).length) return user ? `${user}/${pw}` : pw;
  const t = (extra.type || '').toLowerCase(), p = extra.params || {};
  if (t === 'password_shadow') {
    const pid = +(p.passwd_id || 0);
    if (pid === 2) return hex('sha1', pw);
    if (pid === 3 && user && mac12.length === 12)
      return hex('sha1', hex('md5', user) + '_' + mac12.match(/../g).join(':').toUpperCase());
    return pw;
  }
  if (t === 'password_sha_with_salt') {
    const name = +(p.sha_name ?? -1) === 0 ? 'admin' : 'user';
    try { return hex('sha256', name + Buffer.from(p.sha_salt || '', 'base64').toString() + pw); } catch { return pw; }
  }
  return user ? `${user}/${pw}` : pw;
}

// ---------- Client ----------
class TpapSession {
  constructor(ip, user, pass, port = 80) {
    Object.assign(this, { ip, port, user, pass, session: '', cookie: null });
  }

  #post(path, body, binary = false) {
    const data = binary ? body : Buffer.from(JSON.stringify(body));
    const headers = { 'Content-Type': binary ? 'application/octet-stream' : 'application/json', 'Content-Length': data.length };
    if (this.cookie) headers.Cookie = this.cookie;
    return new Promise((resolve, reject) => {
      const req = http.request({ host: this.ip, port: this.port, path, method: 'POST', headers, agent: false, timeout: 15000 }, res => {
        const ch = [];
        res.on('data', c => ch.push(c));
        res.on('end', () => {
          const buf = Buffer.concat(ch);
          const sc = [].concat(res.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');
          if (sc) this.cookie = sc;
          dbg(`POST ${path} -> ${res.statusCode} (${buf.length}B)`);
          if (res.statusCode !== 200) return reject(new Error(`${path}: HTTP ${res.statusCode} ${buf}`));
          if (binary) return resolve(buf);
          try { resolve(JSON.parse(buf)); } catch { reject(new Error(`${path}: keine JSON-Antwort`)); }
        });
      });
      req.on('timeout', () => req.destroy(new Error(`${path}: Timeout`)));
      req.on('error', reject);
      req.end(data);
    });
  }

  async #login(params) {
    const r = await this.#post('/', { method: 'login', params });
    if (r.error_code) throw new Error(`${params.sub_method} fehlgeschlagen: ${JSON.stringify(r)}`);
    return r.result;
  }

  async discover() {
    const r = await this.#login({ sub_method: 'discover' });
    this.mac = (r.mac || '').replace(/[-:]/g, '');
    this.pake = r.tpap?.pake || [];
    dbg('discover:', JSON.stringify(r));
    return r;
  }

  async authenticate() {
    if (!this.pake) await this.discover();
    const ptype = this.pake.includes(0) ? 'default_userpw' : this.pake.includes(2) ? 'userpw'
      : this.pake.includes(3) ? 'shared_token' : 'userpw';
    const ur = crypto.randomBytes(32);

    // 1) pake_register
    const r = await this.#login({
      sub_method: 'pake_register', username: hex('md5', 'admin'), user_random: ur.toString('base64'),
      cipher_suites: [1], encryption: ['aes_128_ccm', 'chacha20_poly1305', 'aes_256_ccm'],
      passcode_type: ptype, stok: null,
    });
    const st = +(r.cipher_suites || 2), iters = +(r.iterations || 10000);
    this.cipherId = (r.encryption || 'aes_128_ccm').toLowerCase().replace(/-/g, '_');
    const halg = [2, 4, 5, 7, 9].includes(st) ? 'sha512' : 'sha256';
    const useCmac = st === 8 || st === 9, dlen = halg === 'sha512' ? 64 : 32;
    dbg(`pake_register: suite=${st} iters=${iters} enc=${this.cipherId} hkdf=${halg} extra=${JSON.stringify(r.extra_crypt)}`);
    if (!CIPHERS[this.cipherId]) throw new Error(`Unbekannte Verschlüsselung: ${this.cipherId}`);

    // 2) SPAKE2+ Client-Seite
    const cred = buildCred(r.extra_crypt, this.user, this.pass, this.mac);
    const ab = crypto.pbkdf2Sync(Buffer.from(cred), Buffer.from(r.dev_salt, 'base64'), iters, 80, 'sha256');
    const w = mod(b2n(ab.subarray(0, 40)), ORDER), h = mod(b2n(ab.subarray(40)), ORDER);
    const x = b2n(crypto.randomBytes(32)) % (ORDER - 1n) + 1n;

    const L = add(mul(x, G), mul(w, M));
    const R = decode(Buffer.from(r.dev_share, 'base64'));
    const Rp = add(R, neg(mul(w, N)));
    const [Lenc, Renc] = [encode(L), encode(R)];
    const Zenc = encode(mul(x, Rp)), Venc = encode(mul(h, Rp));

    const ctx = hash(halg, Buffer.concat([Buffer.from('PAKE V1'), ur, Buffer.from(r.dev_random, 'base64')]));
    const T = hash(halg, Buffer.concat([ctx, Buffer.alloc(0), Buffer.alloc(0), encode(M), encode(N), Lenc, Renc, Zenc, Venc, encodeW(w)].map(l8)));

    const ml = useCmac ? 16 : 32;
    const conf = hkdf(halg, T, Buffer.alloc(ml * 2), 'ConfirmationKeys', ml * 2);
    const shared = hkdf(halg, T, Buffer.alloc(dlen), 'SharedKey', dlen);
    const macFn = (k, d) => useCmac ? cmac(k, d) : crypto.createHmac(halg, k).update(d).digest();

    // 3) pake_share + Bestätigung prüfen
    const s = await this.#login({
      sub_method: 'pake_share', user_share: Lenc.toString('base64'),
      user_confirm: macFn(conf.subarray(0, ml), Renc).toString('base64'),
    });
    const expected = macFn(conf.subarray(ml, 2 * ml), Lenc).toString('base64');
    if ((s.dev_confirm || '').toLowerCase() !== expected.toLowerCase())
      throw new Error('SPAKE2+ Bestätigung passt nicht -> E-Mail/Passwort falsch');

    this.session = s.sessionId || s.stok || '';
    this.seq = +(s.start_seq || 1);
    const c = CIPHERS[this.cipherId];
    this.key = hkdf(halg, shared, `tp-kdf-salt-${c.tag}-key`, `tp-kdf-info-${c.tag}-key`, c.kl);
    this.nonce = hkdf(halg, shared, `tp-kdf-salt-${c.tag}-iv`, `tp-kdf-info-${c.tag}-iv`, 12);
    dbg(`AUTH OK session=${this.session.slice(0, 8)}... seq=${this.seq}`);
  }

  #aead(dec, seq, data) {
    const iv = Buffer.from(this.nonce); iv.writeUInt32BE(seq >>> 0, 8);
    const alg = CIPHERS[this.cipherId].node, opt = { authTagLength: 16 };
    if (!dec) { const c = crypto.createCipheriv(alg, this.key, iv, opt); return Buffer.concat([c.update(data), c.final(), c.getAuthTag()]); }
    const d = crypto.createDecipheriv(alg, this.key, iv, opt);
    d.setAuthTag(data.subarray(-16));
    return Buffer.concat([d.update(data.subarray(0, -16)), d.final()]);
  }

  async request(method, params = {}) {
    if (!this.session) await this.authenticate();
    const seqBuf = Buffer.alloc(4); seqBuf.writeUInt32BE(this.seq >>> 0);
    const ct = this.#aead(false, this.seq, Buffer.from(JSON.stringify({ method, params })));
    const raw = await this.#post(`/stok=${this.session}/ds`, Buffer.concat([seqBuf, ct]), true);
    if (raw.length < 20) throw new Error(`Antwort zu kurz (${raw.length}B)`);
    const resp = JSON.parse(this.#aead(true, raw.readUInt32BE(0), raw.subarray(4)));
    this.seq++;
    if (resp.error_code) throw new Error(`${method}: error_code ${resp.error_code}`);
    return resp.result;
  }

  getInfo() { return this.request('get_device_info'); }
  setOn(on) { return this.request('set_device_info', { device_on: on }); }
}

module.exports = { TpapSession };

if (require.main === module) {
  const [ip, cmd = 'info', json] = process.argv.slice(2);
  const { TAPO_USER: u, TAPO_PASS: p } = process.env;
  if (!ip || !u || !p) {
    console.error('Nutzung: TAPO_USER=mail TAPO_PASS=pw node tapo-tpap.js <ip> [on|off|info|<methode> [json]]');
    process.exit(1);
  }
  (async () => {
    const dev = new TpapSession(ip, u, p);
    if (!['on', 'off', 'info'].includes(cmd)) return console.log(JSON.stringify(await dev.request(cmd, json ? JSON.parse(json) : {}), null, 2));
    if (cmd !== 'info') await dev.setOn(cmd === 'on');
    const i = await dev.getInfo();
    console.log(`${Buffer.from(i.nickname || '', 'base64')} | ${i.model} | FW ${i.fw_ver} | an: ${i.device_on}`);
  })().catch(e => { console.error('Fehler:', e.message); process.exit(1); });
}
