import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createServer, loadConfig } from '../src/server.js';
import { decryptGcm } from '../src/identityCrypto.js';
import { buildHmacStringToSign, signHmac, splitCanonicalURI } from '../src/signature.js';

// Test vectors (same values as in README)
const KEY = '0123456789abcdef0123456789abcdef';
const NONCE = 'AAECAwQFBgcICQoL';
const CT = 'VsfUDLx2m8iK5lPRJL+XPJNFdsZ28yvGEqzD1ol0lf7zwWF7GoN4Mr0H1jW0xYJKXKL50zKS+KtGKhkqeXZwTp0zRkyqUHz7FpxuQy1JTZh+LJDU';
const PLAIN = '{"openId":"oUpF8uMuAJO_M2pxb1Q9zNjWeS6o","miniAppId":"mini-demo001"}';
const APP = 'app-demo001';
const envelope = (ciphertext = CT, nonce = NONCE) => ({ algorithm: 'AEAD_AES_256_GCM', ciphertext, nonce });

test('GCM golden vector decrypts', () => {
  assert.equal(decryptGcm(CT, NONCE, Buffer.from(KEY)), PLAIN);
});

test('GCM interop: node-sealed envelope with empty AAD opens', () => {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', Buffer.from(KEY), nonce);
  const ct = Buffer.concat([c.update('hello'), c.final(), c.getAuthTag()]);
  assert.equal(decryptGcm(ct.toString('base64'), nonce.toString('base64'), Buffer.from(KEY)), 'hello');
});

test('HMAC golden vector 1 and URI canonicalization', () => {
  const body = Buffer.from('{"userId":"user-001","encryptedData":{"algorithm":"AEAD_AES_256_GCM","ciphertext":"VsfUDLx2m8iK5lPRJL+XPJNFdsZ28yvGEqzD1ol0lf7zwWF7GoN4Mr0H1jW0xYJKXKL50zKS+KtGKhkqeXZwTp0zRkyqUHz7FpxuQy1JTZh+LJDU","nonce":"AAECAwQFBgcICQoL"}}');
  const s1 = buildHmacStringToSign({ method: 'POST', applicationId: APP, timestamp: '1721234567890', body, requestURI: '/superapp/inner/user/checkUser' });
  assert.equal(signHmac(KEY, s1), '979d739e66a1e2709f855e829f50d146ac825e6c140dbef3a1df4cdbe042f59f');
  assert.equal(splitCanonicalURI('/p?name=%E5%BC%A0%20%E4%B8%89&b=2&a=1&a=0').query, 'a=0&a=1&b=2&name=%E5%BC%A0%20%E4%B8%89');
});

test('canonical URI rejects bad input', () => {
  assert.throws(() => splitCanonicalURI('/p?a=%zz'));
  assert.throws(() => splitCanonicalURI('/p?a=%ff'));
  assert.throws(() => splitCanonicalURI('/p#x'));
  assert.equal(splitCanonicalURI('/p?a=1+2').query, 'a=1%2B2');
});

const sign = (raw, ts) => signHmac(KEY, buildHmacStringToSign({
  method: 'POST', requestURI: '/user/checkUser', applicationId: APP, timestamp: ts, body: Buffer.from(raw) }));

async function post(cfg, { raw, headers, path = '/user/checkUser' }, store) {
  const srv = createServer(cfg, store);
  await new Promise((r) => srv.listen(0, r));
  const resp = await fetch(`http://127.0.0.1:${srv.address().port}${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: raw });
  const json = await resp.json();
  srv.close();
  return json;
}

// signed=true: HMAC over raw body; signed=false: no signature headers
async function call(cfg, { body = { userId: 'u1', encryptedData: envelope() }, signed = true, ts = String(Date.now()) } = {}, store) {
  const raw = JSON.stringify(body);
  const headers = signed ? { 'TC-Timestamp': ts, 'TC-ApplicationID': APP, 'TC-Signature': sign(raw, ts) } : {};
  return post(cfg, { raw, headers }, store);
}

const env = { SIGN_KEY: KEY, DATA_ENCRYPT_KEY: KEY, USERS: 'u1', APPLICATION_ID: APP };
const cfg = (o = {}) => loadConfig({ ...env, ...o });

test('HMAC + body encryptedData + existing user', async () => {
  const r = await call(cfg());
  assert.equal(r.returnCode, '0'); assert.equal(r.data, true);
});

test('unknown user -> false', async () => {
  assert.equal((await call(cfg(), { body: { userId: 'x', encryptedData: envelope() } })).data, false);
});

test('HMAC: tampered body rejected (swapped envelope after signing)', async () => {
  const ts = String(Date.now());
  const signedRaw = JSON.stringify({ userId: 'u1', encryptedData: envelope() });
  const tamperedRaw = JSON.stringify({ userId: 'u1', encryptedData: envelope(CT, 'AAAAAAAAAAAAAAAA') });
  const r = await post(cfg(), { raw: tamperedRaw, headers: { 'TC-Timestamp': ts, 'TC-ApplicationID': APP, 'TC-Signature': sign(signedRaw, ts) } });
  assert.equal(r.returnCode, '40101');
});

test('HMAC: expired timestamp -> 40102', async () => {
  assert.equal((await call(cfg(), { ts: '1721234567890' })).returnCode, '40102');
});

test('HMAC: unsigned / uppercase-hex signature rejected', async () => {
  assert.equal((await call(cfg(), { signed: false })).returnCode, '40101');
  const ts = String(Date.now()); const raw = JSON.stringify({ userId: 'u1', encryptedData: envelope() });
  const r = await post(cfg(), { raw, headers: { 'TC-Timestamp': ts, 'TC-ApplicationID': APP, 'TC-Signature': sign(raw, ts).toUpperCase() } });
  assert.equal(r.returnCode, '40101');
});

test('HMAC: missing sign key fails closed', async () => {
  assert.equal((await call(cfg({ SIGN_KEY: '' }))).returnCode, '50000');
});

test('32-hex (non-HMAC-SHA256) signature is not accepted', async () => {
  const ts = String(Date.now()); const raw = JSON.stringify({ userId: 'u1', encryptedData: envelope() });
  const r = await post(cfg(), { raw, headers: { 'TC-Timestamp': ts, 'TC-Signature': 'a'.repeat(32) } });
  assert.equal(r.returnCode, '40101');
});

test('tampered GCM ciphertext rejected', async () => {
  const bad = Buffer.from(CT, 'base64'); bad[0] ^= 1;
  const r = await call(cfg(), { body: { userId: 'u1', encryptedData: envelope(bad.toString('base64')) } });
  assert.equal(r.returnCode, '40101');
});

test('unsupported algorithm / bad nonce / wrong key rejected', async () => {
  assert.equal((await call(cfg(), { body: { userId: 'u1', encryptedData: { ...envelope(), algorithm: 'AES_CBC' } } })).returnCode, '40101');
  assert.equal((await call(cfg(), { body: { userId: 'u1', encryptedData: envelope(CT, 'AAEC') } })).returnCode, '40101');
  assert.equal((await call(cfg({ DATA_ENCRYPT_KEY: 'x'.repeat(32) }))).returnCode, '40101');
});

test('encryptedData is optional; missing userId -> 40001', async () => {
  assert.equal((await call(cfg(), { body: { userId: 'u1' } })).data, true);
  assert.equal((await call(cfg(), { body: { encryptedData: envelope() } })).returnCode, '40001');
});

// Custom userStore: records mapping writes, optionally fails
function spyStore({ users = ['u1'], fail = false } = {}) {
  const saved = [];
  return {
    saved,
    async findUser(userId) { if (fail) throw new Error('db down'); return users.includes(userId); },
    async saveOpenIdMapping(m) { saved.push(m); },
  };
}

test('userStore: mapping saved only when user exists and identity present', async () => {
  const store = spyStore();
  assert.equal((await call(cfg(), {}, store)).data, true);
  assert.deepEqual(store.saved, [{ openId: 'oUpF8uMuAJO_M2pxb1Q9zNjWeS6o', miniAppId: 'mini-demo001', userId: 'u1' }]);
  await call(cfg(), { body: { userId: 'x', encryptedData: envelope() } }, store);
  await call(cfg(), { body: { userId: 'u1' } }, store);
  assert.equal(store.saved.length, 1);
});

test('malformed envelope field types are rejected, server keeps running', async () => {
  const c = cfg();
  for (const bad of [{ ciphertext: 123 }, { nonce: null }, { ciphertext: ['x'] }]) {
    assert.equal((await call(c, { body: { userId: 'u1', encryptedData: { ...envelope(), ...bad } } })).returnCode, '40101');
  }
});

test('BASE_PATH: serves <basePath>/user/checkUser and signs the full path', async () => {
  const path = '/superapp/inner/user/checkUser';
  const ts = String(Date.now());
  const raw = JSON.stringify({ userId: 'u1', encryptedData: envelope() });
  const signFor = (p) => signHmac(KEY, buildHmacStringToSign({ method: 'POST', requestURI: p, applicationId: APP, timestamp: ts, body: Buffer.from(raw) }));
  const headers = (p) => ({ 'TC-Timestamp': ts, 'TC-ApplicationID': APP, 'TC-Signature': signFor(p) });
  for (const basePath of ['/superapp/inner', 'superapp/inner/']) {
    const r = await post(cfg({ BASE_PATH: basePath }), { raw, path, headers: headers(path) });
    assert.equal(r.returnCode, '0'); assert.equal(r.data, true);
  }
  // signed without the prefix (e.g. a gateway stripped it) -> mismatch
  assert.equal((await post(cfg({ BASE_PATH: '/superapp/inner' }), { raw, path, headers: headers('/user/checkUser') })).returnCode, '40101');
});

test('missing / invalid DATA_ENCRYPT_KEY -> 50000 (our misconfiguration, not a bad request)', async () => {
  assert.equal((await call(cfg({ DATA_ENCRYPT_KEY: '' }))).returnCode, '50000');
  assert.equal((await call(cfg({ DATA_ENCRYPT_KEY: 'short' }))).returnCode, '50000');
  // no encryptedData in the body -> the data key is not needed
  assert.equal((await call(cfg({ DATA_ENCRYPT_KEY: '' }), { body: { userId: 'u1' } })).data, true);
});

test('userStore: business error -> 50000', async () => {
  assert.equal((await call(cfg(), {}, spyStore({ fail: true }))).returnCode, '50000');
});
