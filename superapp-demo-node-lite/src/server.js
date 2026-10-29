// Lite SuperApp demo: only POST /user/checkUser.
// Flow: verify TC-Signature (HMAC-SHA256) -> decrypt body.encryptedData (AES-256-GCM) -> business.
// Zero dependencies (Node >= 18, 20+ recommended).
//
//   signature.js       TC-Signature verification (protocol, do not change)
//   identityCrypto.js  encryptedData decryption (protocol, do not change)
//   userStore.js       user lookup + openId mapping (REPLACE with your own storage)
//   errorCodes.js      all returnCode values

import http from 'node:http';
import crypto from 'node:crypto';
import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { decryptIdentity, DecryptError } from './identityCrypto.js';
import { verifyRequest, SignError } from './signature.js';
import { createUserStore } from './userStore.js';
import { OK, INVALID_PARAM, SIGN_INVALID, SIGN_EXPIRED, SERVER_ERROR } from './errorCodes.js';

const MAX_BODY = 1 << 20;

// "/superapp/inner/" -> "/superapp/inner", "" or "/" -> ""
function normalizeBasePath(p = '') {
  const trimmed = p.trim().replace(/\/+$/, '');
  return trimmed && !trimmed.startsWith('/') ? `/${trimmed}` : trimmed;
}

export function loadConfig(env = process.env) {
  const key = (v) => (v ? Buffer.from(v, 'utf8') : undefined);
  return {
    port: Number(env.PORT || 9093),
    basePath: normalizeBasePath(env.BASE_PATH),   // path part of the console Domain name, e.g. /superapp/inner
    signKey: env.SIGN_KEY || undefined,            // HMAC secret, 32-255 bytes
    applicationId: env.APPLICATION_ID || '',       // optional: pin TC-ApplicationID
    skewSec: Number(env.SIGNATURE_SKEW_SEC || 300),
    dataEncryptKey: key(env.DATA_ENCRYPT_KEY),     // 32 bytes, AEAD_AES_256_GCM (standard AES-256-GCM)
    users: new Set((env.USERS || 'demo-user-001,demo-user-002').split(',').map((s) => s.trim()).filter(Boolean)),
  };
}

function reply(res, requestId, code, message, data = null) {
  res.writeHead(200, { 'Content-Type': 'application/json', 'TC-TraceID': requestId });
  res.end(JSON.stringify({ returnCode: code, returnMessage: message, data, requestId }));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export function createServer(cfg, userStore = createUserStore(cfg.users)) {
  return http.createServer((req, res) => {
    const requestId = req.headers['tc-traceid'] || crypto.randomBytes(16).toString('hex');
    // Safety net: an unexpected error must fail this request only, never crash the process
    handleRequest(req, res, requestId, cfg, userStore).catch((e) => {
      console.error(`checkUser: unexpected error trace=${requestId}`, e);
      if (!res.headersSent) reply(res, requestId, SERVER_ERROR, 'internal error');
    });
  });
}

async function handleRequest(req, res, requestId, cfg, userStore) {
  const path = (req.url || '').split('?')[0];
  if (req.method !== 'POST' || path !== `${cfg.basePath}/user/checkUser`) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    return res.end('{"error":"not found"}');
  }

  let raw;
  try { raw = await readBody(req); } catch { return reply(res, requestId, INVALID_PARAM, 'invalid parameter'); }

  // 1. verify signature over the raw bytes (before any parsing)
  try {
    verifyRequest(req, raw, cfg);
  } catch (e) {
    if (!(e instanceof SignError)) throw e;
    console.warn(`checkUser: signature rejected trace=${requestId} code=${e.code} reason=${e.message}`);
    const message = { [SIGN_EXPIRED]: 'timestamp expired', [SERVER_ERROR]: 'server misconfigured' }[e.code] || 'signature verification failed';
    return reply(res, requestId, e.code, message);
  }

  // 2. parse body (already authenticated by the signature)
  let body;
  try { body = JSON.parse(raw.toString('utf8') || '{}'); }
  catch { return reply(res, requestId, INVALID_PARAM, 'invalid parameter'); }
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return reply(res, requestId, INVALID_PARAM, 'invalid parameter');

  // 3. decrypt body.encryptedData when present (fail closed on any error)
  if (body.encryptedData != null && cfg.dataEncryptKey?.length !== 32) {
    console.error(`checkUser: DATA_ENCRYPT_KEY is not configured or not 32 bytes trace=${requestId}`);
    return reply(res, requestId, SERVER_ERROR, 'server misconfigured');
  }
  let identity = null;
  try {
    identity = decryptIdentity(body, cfg.dataEncryptKey);
  } catch (e) {
    if (!(e instanceof DecryptError)) throw e;
    console.warn(`checkUser: identity decrypt failed trace=${requestId}`);
    return reply(res, requestId, SIGN_INVALID, 'identity decrypt failed');
  }

  const userId = body.userId;
  if (typeof userId !== 'string' || !userId) return reply(res, requestId, INVALID_PARAM, 'userId is required');

  // 4. business (storage lives in userStore.js -- replace it with your own)
  //    "User does not exist" is a business result: returnCode "0" with data = false.
  try {
    const exists = await userStore.findUser(userId);
    if (exists && identity?.openId && identity?.miniAppId) {
      await userStore.saveOpenIdMapping({ openId: identity.openId, miniAppId: identity.miniAppId, userId });
    }
    console.log(`checkUser: trace=${requestId} userId=${userId} exists=${exists} miniAppId=${identity?.miniAppId ?? ''}`);
    return reply(res, requestId, OK, 'OK', exists);
  } catch (e) {
    console.error(`checkUser: business error trace=${requestId}`, e);
    return reply(res, requestId, SERVER_ERROR, 'internal error');
  }
}

// Start only when run directly (realpath + pathToFileURL handle symlinks, Windows paths and spaces)
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  const cfg = loadConfig();
  // Warn early: a missing / invalid key makes every request fail with 50000
  const signKeyBytes = Buffer.byteLength(cfg.signKey || '', 'utf8');
  if (signKeyBytes < 32 || signKeyBytes > 255) console.warn('WARNING: SIGN_KEY must be 32-255 bytes; all requests will return 50000');
  if (cfg.dataEncryptKey?.length !== 32) console.warn('WARNING: DATA_ENCRYPT_KEY must be exactly 32 bytes; requests with encryptedData will return 50000');
  createServer(cfg).listen(cfg.port, () => console.log(`superapp-demo-node-lite listening on :${cfg.port}, POST ${cfg.basePath}/user/checkUser`));
}
