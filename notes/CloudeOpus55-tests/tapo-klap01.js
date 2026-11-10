#!/usr/bin/env node
// Minimaler Tapo-KLAP-Client (v2) – ohne Abhängigkeiten, Node >= 18 (fetch + crypto)
// Nutzung: TAPO_USER=mail TAPO_PASS=pw node tapo-klap.js <ip> [on|off|info]
'use strict';
const crypto = require('crypto');

const sha = (alg, ...b) => crypto.createHash(alg).update(Buffer.concat(b)).digest();
const s1 = (...b) => sha('sha1', ...b), s256 = (...b) => sha('sha256', ...b);

class KlapSession {
  constructor(ip, user, pass) {
    this.base = `http://${ip}/app`;
    // KLAP v2: sha256(sha1(user) + sha1(pass))
    this.authHash = s256(s1(Buffer.from(user)), s1(Buffer.from(pass)));
  }

  async #post(path, body, extra = {}) {
    const res = await fetch(this.base + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream', ...(this.cookie && { Cookie: this.cookie }), ...extra },
      body,
    });
    if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
    return { res, buf: Buffer.from(await res.arrayBuffer()) };
  }

  async handshake() {
    const local = crypto.randomBytes(16);
    this.cookie = null;

    // handshake1: local_seed -> remote_seed(16) + server_hash(32)
    const { res, buf } = await this.#post('/handshake1', local);
    const sid = (res.headers.get('set-cookie') || '').match(/TP_SESSIONID=([^;]+)/);
    if (!sid) throw new Error('handshake1: kein TP_SESSIONID-Cookie');
    this.cookie = `TP_SESSIONID=${sid[1]}`;
    const remote = buf.subarray(0, 16), serverHash = buf.subarray(16, 48);

    if (!s256(local, remote, this.authHash).equals(serverHash))
      throw new Error('handshake1: Server-Hash passt nicht -> E-Mail/Passwort falsch');

    // handshake2: Gegenbeweis an das Gerät
    await this.#post('/handshake2', s256(remote, local, this.authHash));

    // Sitzungsschlüssel ableiten
    const lh = Buffer.concat([local, remote, this.authHash]);
    this.key = s256(Buffer.from('lsk'), lh).subarray(0, 16);
    const ivFull = s256(Buffer.from('iv'), lh);
    this.iv = ivFull.subarray(0, 12);
    this.seq = ivFull.readInt32BE(28);
    this.sig = s256(Buffer.from('ldk'), lh).subarray(0, 28);
  }

  #ivFor(seq) {
    const s = Buffer.alloc(4); s.writeInt32BE(seq);
    return { iv: Buffer.concat([this.iv, s]), seqBuf: s };
  }

  async request(method, params) {
    if (!this.key) await this.handshake();
    this.seq = this.seq === 0x7fffffff ? -0x80000000 : this.seq + 1;
    const { iv, seqBuf } = this.#ivFor(this.seq);

    const plain = Buffer.from(JSON.stringify({ method, ...(params && { params }), requestTimeMils: Date.now() }));
    const c = crypto.createCipheriv('aes-128-cbc', this.key, iv);
    const enc = Buffer.concat([c.update(plain), c.final()]);
    const body = Buffer.concat([s256(this.sig, seqBuf, enc), enc]);

    const { buf } = await this.#post(`/request?seq=${this.seq}`, body);
    const d = crypto.createDecipheriv('aes-128-cbc', this.key, iv);
    const json = JSON.parse(Buffer.concat([d.update(buf.subarray(32)), d.final()]).toString());
    if (json.error_code !== 0) throw new Error(`${method}: error_code ${json.error_code}`);
    return json.result;
  }

  getInfo()  { return this.request('get_device_info'); }
  setOn(on)  { return this.request('set_device_info', { device_on: on }); }
}

module.exports = { KlapSession };

if (require.main === module) {
  const [ip, cmd = 'info'] = process.argv.slice(2);
  const { TAPO_USER: u, TAPO_PASS: p } = process.env;
  if (!ip || !u || !p) {
    console.error('Nutzung: TAPO_USER=mail TAPO_PASS=pw node tapo-klap.js <ip> [on|off|info]');
    process.exit(1);
  }
  (async () => {
    const dev = new KlapSession(ip, u, p);
    if (cmd === 'on' || cmd === 'off') await dev.setOn(cmd === 'on');
    const i = await dev.getInfo();
    console.log(`${Buffer.from(i.nickname || '', 'base64')} | ${i.model} | FW ${i.fw_ver} | an: ${i.device_on}`);
  })().catch(e => { console.error('Fehler:', e.message); process.exit(1); });
}
