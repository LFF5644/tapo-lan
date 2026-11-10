'use strict';
// tapo.js – Minimale lokale Tapo-Lib (KLAP + TPAP), ohne Abhängigkeiten, Node >= 18
// TPAP-Teil portiert von raymondlo84/tapo-tpap-client (tpap_proto.py)
const crypto = require('crypto');
const http = require('http');
const { EventEmitter } = require('events');

const DEBUG = !!process.env.TAPO_DEBUG;
const dbg = (...a) => DEBUG && console.error('DEBUG', ...a);

// ============================================================================
// Helfer
// ============================================================================
const hash = (alg, ...d) => crypto.createHash(alg).update(Buffer.concat(d)).digest();
const hex = (alg, s) => crypto.createHash(alg).update(s).digest('hex');
const hkdf = (alg, ikm, salt, info, len) => Buffer.from(crypto.hkdfSync(alg, ikm, salt, info, len));
const xor = (a, b) => Buffer.from(a.map((v, i) => v ^ b[i]));

// snake_case -> camelCase (rekursiv), base64-Felder dekodieren
const B64_FIELDS = new Set(['nickname', 'ssid']);
const camel = v => Array.isArray(v) ? v.map(camel)
	: v && typeof v === 'object'
		? Object.fromEntries(Object.entries(v).map(([k, x]) => [
			k.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase()),
			B64_FIELDS.has(k) && typeof x === 'string' ? Buffer.from(x, 'base64').toString() : camel(x)]))
		: v;

class TapoError extends Error {
	constructor(msg, code, kind) { super(msg); this.code = code; this.kind = kind; } // kind: network | auth | session | device
}
const NET_CODES = new Set(['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'ETIMEDOUT', 'ECONNRESET', 'EAI_AGAIN', 'TIMEOUT']);

function post(ip, port, path, body, { json = false, cookie, timeout = 5000 } = {}) {
	const data = json ? Buffer.from(JSON.stringify(body)) : body;
	const headers = { 'Content-Type': json ? 'application/json' : 'application/octet-stream', 'Content-Length': data.length };
	if (cookie) headers.Cookie = cookie;
	return new Promise((resolve, reject) => {
		const req = http.request({ host: ip, port, path, method: 'POST', headers, agent: false, timeout }, res => {
			const ch = [];
			res.on('data', c => ch.push(c));
			res.on('end', () => {
				const buf = Buffer.concat(ch);
				dbg(`POST ${path} -> ${res.statusCode} (${buf.length}B)`);
				resolve({ status: res.statusCode, headers: res.headers, buf });
			});
		});
		req.on('timeout', () => req.destroy(Object.assign(new Error('Timeout'), { code: 'TIMEOUT' })));
		req.on('error', e => reject(new TapoError(`${path}: ${e.message}`, e.code, 'network')));
		req.end(data);
	});
}

// ============================================================================
// KLAP (mit "Third-Party Compatibility")
// ============================================================================
class Klap {
	constructor(ip, port, user, pass) {
		Object.assign(this, { ip, port, name: 'klap' });
		this.authHash = hash('sha256', hash('sha1', Buffer.from(user)), hash('sha1', Buffer.from(pass)));
	}

	async login() {
		const local = crypto.randomBytes(16);
		const h1 = await post(this.ip, this.port, '/app/handshake1', local);
		if (h1.status !== 200) throw new TapoError(`handshake1: HTTP ${h1.status}`, h1.status, 'auth');
		const sid = [].concat(h1.headers['set-cookie'] || []).join(';').match(/TP_SESSIONID=([^;]+)/);
		if (!sid) throw new TapoError('handshake1: kein TP_SESSIONID', 0, 'auth');
		this.cookie = `TP_SESSIONID=${sid[1]}`;
		const remote = h1.buf.subarray(0, 16);
		if (!hash('sha256', local, remote, this.authHash).equals(h1.buf.subarray(16, 48)))
			throw new TapoError('KLAP: E-Mail/Passwort falsch', 0, 'auth');

		const h2 = await post(this.ip, this.port, '/app/handshake2', hash('sha256', remote, local, this.authHash), { cookie: this.cookie });
		if (h2.status !== 200) throw new TapoError(`handshake2: HTTP ${h2.status}`, h2.status, 'auth');

		const lh = Buffer.concat([local, remote, this.authHash]);
		this.key = hash('sha256', Buffer.from('lsk'), lh).subarray(0, 16);
		const iv = hash('sha256', Buffer.from('iv'), lh);
		this.iv = iv.subarray(0, 12);
		this.seq = iv.readInt32BE(28);
		this.sig = hash('sha256', Buffer.from('ldk'), lh).subarray(0, 28);
	}

	async send(method, params) {
		this.seq = this.seq === 0x7fffffff ? -0x80000000 : this.seq + 1;
		const s = Buffer.alloc(4); s.writeInt32BE(this.seq);
		const iv = Buffer.concat([this.iv, s]);
		const c = crypto.createCipheriv('aes-128-cbc', this.key, iv);
		const enc = Buffer.concat([c.update(JSON.stringify({ method, ...(params && { params }), requestTimeMils: Date.now() })), c.final()]);
		const r = await post(this.ip, this.port, `/app/request?seq=${this.seq}`, Buffer.concat([hash('sha256', this.sig, s, enc), enc]), { cookie: this.cookie });
		if (r.status !== 200) throw new TapoError(`request: HTTP ${r.status}`, r.status, 'session');
		const d = crypto.createDecipheriv('aes-128-cbc', this.key, iv);
		return JSON.parse(Buffer.concat([d.update(r.buf.subarray(32)), d.final()]));
	}
}

// ============================================================================
// TPAP (SPAKE2+ auf P-256) – ohne "Third-Party Compatibility"
// ============================================================================
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const G = {
	x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
	y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
};
const mod = (a, m = P) => ((a % m) + m) % m;
const inv = a => {
	let [r0, r1, s0, s1] = [mod(a), P, 1n, 0n];
	while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
	return mod(s0);
};
const add = (p, q) => {
	if (!p) return q; if (!q) return p;
	if (p.x === q.x && mod(p.y + q.y) === 0n) return null;
	const l = p.x === q.x ? mod((3n * p.x * p.x - 3n) * inv(2n * p.y)) : mod((q.y - p.y) * inv(q.x - p.x));
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
const decodePt = buf => {
	const u = crypto.ECDH.convertKey(buf, 'prime256v1', undefined, undefined, 'uncompressed');
	return { x: b2n(u.subarray(1, 33)), y: b2n(u.subarray(33, 65)) };
};
const encodePt = p => Buffer.concat([Buffer.from([4]), n2b(p.x, 32), n2b(p.y, 32)]);
const M = decodePt(Buffer.from('02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f', 'hex'));
const N = decodePt(Buffer.from('03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49', 'hex'));
const l8 = b => { const h = Buffer.alloc(8); h.writeBigUInt64LE(BigInt(b.length)); return Buffer.concat([h, b]); };
const encodeW = w => {
	const h = w.toString(16), u = Buffer.from(h.length % 2 ? '0' + h : h, 'hex');
	return (u.length % 2 && u[0] & 0x80) ? Buffer.concat([Buffer.from([0]), u]) : u;
};
const cmac = (key, msg) => { // AES-CMAC (RFC 4493)
	const alg = `aes-${key.length * 8}-ecb`;
	const enc = b => { const c = crypto.createCipheriv(alg, key, null); c.setAutoPadding(false); return Buffer.concat([c.update(b), c.final()]); };
	const dbl = b => { const o = Buffer.alloc(16); for (let i = 0; i < 16; i++) o[i] = (b[i] << 1) | (i < 15 ? b[i + 1] >> 7 : 0); if (b[0] & 0x80) o[15] ^= 0x87; return o; };
	const k1 = dbl(enc(Buffer.alloc(16))), k2 = dbl(k1);
	const n = Math.max(1, Math.ceil(msg.length / 16)), full = msg.length > 0 && msg.length % 16 === 0;
	const last = Buffer.alloc(16); msg.copy(last, 0, (n - 1) * 16);
	if (!full) last[msg.length - (n - 1) * 16] = 0x80;
	let x = Buffer.alloc(16);
	for (let i = 0; i < n - 1; i++) x = enc(xor(x, msg.subarray(i * 16, i * 16 + 16)));
	return enc(xor(x, xor(last, full ? k1 : k2)));
};
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

async function discover(ip, port) { // ohne Zugangsdaten -> kein Login-Versuch
	const r = await post(ip, port, '/', { method: 'login', params: { sub_method: 'discover' } }, { json: true, timeout: 3000 });
	if (r.status !== 200) return null;
	try { const j = JSON.parse(r.buf); return j.error_code ? null : j.result; } catch { return null; }
}

class Tpap {
	constructor(ip, port, user, pass, info) {
		Object.assign(this, { ip, port, user, pass, name: 'tpap' });
		this.mac = (info?.mac || '').replace(/[-:]/g, '');
		this.pake = info?.tpap?.pake || [];
	}

	async #login(params) {
		const r = await post(this.ip, this.port, '/', { method: 'login', params }, { json: true, timeout: 15000 });
		if (r.status !== 200) throw new TapoError(`${params.sub_method}: HTTP ${r.status}`, r.status, 'auth');
		const j = JSON.parse(r.buf);
		if (j.error_code) throw new TapoError(`${params.sub_method}: error_code ${j.error_code}`, j.error_code, 'auth');
		return j.result;
	}

	async login() {
		const ptype = this.pake.includes(0) ? 'default_userpw' : this.pake.includes(3) && !this.pake.includes(2) ? 'shared_token' : 'userpw';
		const ur = crypto.randomBytes(32);
		const r = await this.#login({
			sub_method: 'pake_register', username: hex('md5', 'admin'), user_random: ur.toString('base64'),
			cipher_suites: [1], encryption: ['aes_128_ccm', 'chacha20_poly1305', 'aes_256_ccm'], passcode_type: ptype, stok: null,
		});
		const st = +(r.cipher_suites || 2), iters = +(r.iterations || 10000);
		this.cipherId = (r.encryption || 'aes_128_ccm').toLowerCase().replace(/-/g, '_');
		const c = CIPHERS[this.cipherId];
		if (!c) throw new TapoError(`Unbekannte Verschlüsselung: ${this.cipherId}`, 0, 'auth');
		const halg = [2, 4, 5, 7, 9].includes(st) ? 'sha512' : 'sha256';
		const useCmac = st === 8 || st === 9, dlen = halg === 'sha512' ? 64 : 32, ml = useCmac ? 16 : 32;
		dbg(`pake_register: suite=${st} iters=${iters} enc=${this.cipherId} extra=${JSON.stringify(r.extra_crypt)}`);

		const cred = buildCred(r.extra_crypt, this.user, this.pass, this.mac);
		const ab = crypto.pbkdf2Sync(Buffer.from(cred), Buffer.from(r.dev_salt, 'base64'), iters, 80, 'sha256');
		const w = mod(b2n(ab.subarray(0, 40)), ORDER), h = mod(b2n(ab.subarray(40)), ORDER);
		const x = b2n(crypto.randomBytes(32)) % (ORDER - 1n) + 1n;

		const L = add(mul(x, G), mul(w, M)), R = decodePt(Buffer.from(r.dev_share, 'base64'));
		const Rp = add(R, neg(mul(w, N)));
		const Lenc = encodePt(L), Renc = encodePt(R);
		const ctx = hash(halg, Buffer.from('PAKE V1'), ur, Buffer.from(r.dev_random, 'base64'));
		const T = hash(halg, ...[ctx, Buffer.alloc(0), Buffer.alloc(0), encodePt(M), encodePt(N), Lenc, Renc,
			encodePt(mul(x, Rp)), encodePt(mul(h, Rp)), encodeW(w)].map(l8));
		const conf = hkdf(halg, T, Buffer.alloc(ml * 2), 'ConfirmationKeys', ml * 2);
		const shared = hkdf(halg, T, Buffer.alloc(dlen), 'SharedKey', dlen);
		const macFn = (k, d) => useCmac ? cmac(k, d) : crypto.createHmac(halg, k).update(d).digest();

		const s = await this.#login({
			sub_method: 'pake_share', user_share: Lenc.toString('base64'),
			user_confirm: macFn(conf.subarray(0, ml), Renc).toString('base64'),
		});
		if ((s.dev_confirm || '').toLowerCase() !== macFn(conf.subarray(ml), Lenc).toString('base64').toLowerCase())
			throw new TapoError('TPAP: E-Mail/Passwort falsch', 0, 'auth');

		this.session = s.sessionId || s.stok || '';
		this.seq = +(s.start_seq || 1);
		this.key = hkdf(halg, shared, `tp-kdf-salt-${c.tag}-key`, `tp-kdf-info-${c.tag}-key`, c.kl);
		this.nonce = hkdf(halg, shared, `tp-kdf-salt-${c.tag}-iv`, `tp-kdf-info-${c.tag}-iv`, 12);
	}

	#aead(dec, seq, data) {
		const iv = Buffer.from(this.nonce); iv.writeUInt32BE(seq >>> 0, 8);
		const alg = CIPHERS[this.cipherId].node, opt = { authTagLength: 16 };
		if (!dec) { const c = crypto.createCipheriv(alg, this.key, iv, opt); return Buffer.concat([c.update(data), c.final(), c.getAuthTag()]); }
		const d = crypto.createDecipheriv(alg, this.key, iv, opt);
		d.setAuthTag(data.subarray(-16));
		return Buffer.concat([d.update(data.subarray(0, -16)), d.final()]);
	}

	async send(method, params) {
		const s = Buffer.alloc(4); s.writeUInt32BE(this.seq >>> 0);
		const ct = this.#aead(false, this.seq, Buffer.from(JSON.stringify({ method, params: params || {} })));
		const r = await post(this.ip, this.port, `/stok=${this.session}/ds`, Buffer.concat([s, ct]), { timeout: 15000 });
		if (r.status !== 200 || r.buf.length < 20) throw new TapoError(`ds: HTTP ${r.status} (${r.buf.length}B)`, r.status, 'session');
		let plain;
		try { plain = this.#aead(true, r.buf.readUInt32BE(0), r.buf.subarray(4)); }
		catch { throw new TapoError('ds: Entschlüsselung fehlgeschlagen', 0, 'session'); }
		this.seq++;
		return JSON.parse(plain);
	}
}

// ============================================================================
// Geräte
// ============================================================================
// Watch-Topics: Name -> Getter-Methode (Event-Name = Topic-Name)
const TOPICS = {
	state: 'getState', info: 'getInfo', deviceUsage: 'getDeviceUsage',
	currentPower: 'getCurrentPower', energyUsage: 'getEnergyUsage',
};
const SESSION_ERR = new Set([-1012, -1301, 9999, 1002, 1003]); // Session ungültig/abgelaufen

class TapoDevice extends EventEmitter {
	constructor(hub, ip, opts) {
		super();
		Object.assign(this, { hub, ip, port: opts.port || 80, name: opts.name || ip, protocol: opts.protocol || 'auto' });
		this.online = null;      // null = unbekannt
		this.model = null;
		this.last = {};          // letzte Werte je Topic
		this.watches = new Map(); // topic -> { ms, timer }
		this.authBlocked = false; // nach falschem Passwort: kein Hintergrund-Login mehr
		this.queue = Promise.resolve();
	}

	// ---------- Kern ----------
	_emit(ev, ...a) { this.emit(ev, ...a); this.hub.emit(ev, this, ...a); }

	#setOnline(on, err) {
		if (this.online === on) return;
		const was = this.online; this.online = on;
		if (on && was === false) this._emit('online');
		if (!on) this._emit('offline', err);
	}

	async #connect() {
		let proto = this.protocol, info = null;
		if (proto !== 'klap') {
			info = await discover(this.ip, this.port).catch(e => { if (e.kind === 'network') throw e; return null; });
			if (proto === 'auto') proto = info?.tpap_preferred ? 'tpap' : 'klap';
		}
		const { user, pass } = this.hub;
		this.t = proto === 'tpap' ? new Tpap(this.ip, this.port, user, pass, info) : new Klap(this.ip, this.port, user, pass);
		await this.t.login();
		this.authBlocked = false;
		dbg(`${this.name}: Login OK (${proto})`);
	}

	// Ein Request: Warteschlange, max. 1x Re-Login bei abgelaufener Session
	request(method, params) {
		const run = async () => {
			try {
				if (!this.t) await this.#connect();
				let res;
				try {
					res = await this.t.send(method, params);
					if (SESSION_ERR.has(res.error_code)) throw new TapoError(`error_code ${res.error_code}`, res.error_code, 'session');
				} catch (e) {
					if (e.kind !== 'session') throw e;
					dbg(`${this.name}: Session abgelaufen -> Re-Login`);
					this.t = null;
					await this.#connect();
					this._emit('reauth');
					res = await this.t.send(method, params);
				}
				this.#setOnline(true);
				if (res.error_code) throw new TapoError(`${method}: error_code ${res.error_code}`, res.error_code, 'device');
				return res.result;
			} catch (e) {
				if (e.kind === 'network' || NET_CODES.has(e.code)) { this.t = null; this.#setOnline(false, e); }
				else if (e.kind === 'auth') { this.t = null; this.authBlocked = true; }
				throw e;
			}
		};
		const p = this.queue.then(run, run);
		this.queue = p.catch(() => {});
		return p;
	}

	// (intern) Wert speichern + Events ('<topic>' immer, 'change' nur bei Änderung)
	_publish(topic, value) {
		const old = this.last[topic];
		this.last[topic] = value;
		this._emit(topic, value, old);
		if (JSON.stringify(old) !== JSON.stringify(value)) this._emit('change', topic, value, old);
		return value;
	}

	// ---------- API (alle Geräte) ----------
	async getInfo() {
		const i = camel(await this.request('get_device_info'));
		this.model = i.model;
		this._publish('state', i.deviceOn);
		return this._publish('info', i);
	}
	async getState() { return this._publish('state', (await this.request('get_device_info')).device_on); }
	async getDeviceUsage() { return this._publish('deviceUsage', camel(await this.request('get_device_usage'))); }

	async setState(on) { await this.request('set_device_info', { device_on: !!on }); return this._publish('state', !!on); }
	turnOn() { return this.setState(true); }
	turnOff() { return this.setState(false); }
	async toggle() { return this.setState(!(await this.getState())); }

	// ---------- Watch ----------
	// watch(5e3, 'state', 'info')  -> eigener Timer pro Topic; erneutes watch ersetzt das Intervall
	watch(ms, ...topics) {
		if (!(ms > 0)) throw new TypeError('watch(ms, ...topics): ms muss > 0 sein');
		for (const t of topics.flat()) {
			if (!TOPICS[t] || typeof this[TOPICS[t]] !== 'function') throw new TypeError(`${this.name}: Topic "${t}" nicht unterstützt (${this.topics.join(', ')})`);
			this.unwatch(t);
			const w = { ms, busy: false };
			const tick = async () => {
				if (w.busy || this.authBlocked) return; // nach Auth-Fehler: Hintergrund pausiert, bis ein expliziter Aufruf klappt
				w.busy = true;
				try { await this[TOPICS[t]](); } catch (e) { if (e.kind !== 'network') this._emit('error', e); }
				finally { w.busy = false; }
			};
			w.timer = setInterval(tick, ms);
			this.watches.set(t, w);
			tick();
		}
		return this;
	}

	// unwatch('energyUsage') | unwatch() = alle
	unwatch(...topics) {
		const list = topics.flat().length ? topics.flat() : [...this.watches.keys()];
		for (const t of list) { clearInterval(this.watches.get(t)?.timer); this.watches.delete(t); }
		return this;
	}

	get topics() { return Object.keys(TOPICS).filter(t => typeof this[TOPICS[t]] === 'function'); }
	get watching() { return Object.fromEntries([...this.watches].map(([t, w]) => [t, w.ms])); }

	// Fehler ohne Listener nicht als Crash werfen
	emit(ev, ...a) { if (ev === 'error' && !this.listenerCount('error')) return false; return super.emit(ev, ...a); }
}

class P100 extends TapoDevice {}

class P110 extends P100 {
	async getCurrentPower() { return this._publish('currentPower', camel(await this.request('get_current_power'))); }
	async getEnergyUsage() { return this._publish('energyUsage', camel(await this.request('get_energy_usage'))); }
}

const MODELS = { P100, P105: P100, P110, P110M: P110, P115: P110 };

// ============================================================================
// Hub
// ============================================================================
class Tapo extends EventEmitter {
	constructor({ user, pass }) {
		super();
		if (!user || !pass) throw new TypeError('Tapo({ user, pass }) erforderlich');
		Object.assign(this, { user, pass, devices: new Map() });
	}

	// Verbindet, erkennt Modell -> P100/P110-Instanz
	async connect(ip, opts = {}) {
		const probe = new TapoDevice(this, ip, opts);
		const info = camel(await probe.request('get_device_info'));
		const Cls = MODELS[info.model] || TapoDevice;
		const dev = new Cls(this, ip, { ...opts, name: opts.name || info.nickname || ip });
		Object.assign(dev, { t: probe.t, model: info.model, online: true });
		dev.last.info = info; dev.last.state = info.deviceOn;
		this.devices.set(dev.name, dev);
		return dev;
	}

	device(name) { return this.devices.get(name); }
	unwatchAll() { for (const d of this.devices.values()) d.unwatch(); return this; }

	emit(ev, ...a) { if (ev === 'error' && !this.listenerCount('error')) return false; return super.emit(ev, ...a); }
}

module.exports = { Tapo, TapoDevice, P100, P110, TapoError, _internal: { Tpap, Klap, discover, mul, add, neg, G, M, N, ORDER, encodePt, decodePt, b2n, mod, l8, encodeW, hash, hkdf, cmac, buildCred, CIPHERS } };
