// Request signature verification (platform -> your server).
//
// Algorithm: HMAC-SHA256
//
//   TC-Signature = lowercase_hex( HMAC-SHA256( key = SIGN_KEY, message = StringToSign ) )
//
// StringToSign is 7 lines, each line ends with "\n" (including the last one):
//
//   1  TC-SIGN-V1:P2S                  fixed protocol tag (P2S = platform to your server)
//   2  POST                            HTTP method, upper case
//   3  /user/checkUser                 request path, exactly as received (not decoded, not cleaned)
//   4  a=1&b=2                         query string, normalized (see below); empty line if no query
//   5  app-demo001                     header TC-ApplicationID
//   6  1721234567890                   header TC-Timestamp, used as received (13-digit ms)
//   7  de5522bc...a7dc538              lowercase_hex( SHA-256( raw request body bytes ) )
//
// Query normalization (line 4): split into key=value pairs -> URL-decode each key and value
// -> URL-encode again (uppercase %XX, space = %20, '+' stays a literal plus) -> sort by key,
// then by value -> join with '&'.
//
// Your checks, in order: required headers -> timestamp window -> HMAC compare -> done.
// Compare signatures in constant time and accept lowercase hex only.
//
// Worked example (key = 0123456789abcdef0123456789abcdef, app = app-demo001, ts = 1721234567890,
// POST /superapp/inner/user/checkUser, body = {"userId":"user-001","encryptedData":{"algorithm":"AEAD_AES_256_GCM","ciphertext":"VsfUDLx2m8iK5lPRJL+XPJNFdsZ28yvGEqzD1ol0lf7zwWF7GoN4Mr0H1jW0xYJKXKL50zKS+KtGKhkqeXZwTp0zRkyqUHz7FpxuQy1JTZh+LJDU","nonce":"AAECAwQFBgcICQoL"}}):
//   TC-Signature = 979d739e66a1e2709f855e829f50d146ac825e6c140dbef3a1df4cdbe042f59f
// (/superapp/inner is only an example prefix: the signed path is whatever path the platform requests.)

import crypto from 'node:crypto';
import { SIGN_INVALID, SIGN_EXPIRED, SERVER_ERROR } from './errorCodes.js';

export class SignError extends Error {
  constructor(code, msg) { super(msg); this.code = code; }
}

// ---------------------------------------------------------------------------
// Step 1: normalize the query string (line 4 of StringToSign)
// ---------------------------------------------------------------------------

/** URL-decode one query component. '+' is NOT turned into a space; bad %XX or bad UTF-8 is rejected. */
function decodeComponent(s) {
  if (/%(?![0-9a-fA-F]{2})/.test(s)) throw new SignError(SIGN_INVALID, 'invalid query');
  const bytes = Buffer.from(s.replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))), 'latin1');
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { throw new SignError(SIGN_INVALID, 'invalid query'); }
}

/** URL-encode one query component: keep A-Z a-z 0-9 - _ . ~ and write every other UTF-8 byte as %XX (uppercase). */
function encodeComponent(s) {
  let out = '';
  for (const b of Buffer.from(s, 'utf8')) {
    const c = String.fromCharCode(b);
    out += /[A-Za-z0-9\-_.~]/.test(c) ? c : '%' + b.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}

const compareBytes = (a, b) => (a === b ? 0 : Buffer.compare(Buffer.from(a), Buffer.from(b)));

/** Split "/path?query" into the untouched path and the normalized query. */
export function splitCanonicalURI(requestURI) {
  if (requestURI.includes('#')) throw new SignError(SIGN_INVALID, 'fragment not allowed');
  const i = requestURI.indexOf('?');
  let path = i < 0 ? requestURI : requestURI.slice(0, i);
  const rawQuery = i < 0 ? '' : requestURI.slice(i + 1);
  if (path === '') path = '/';

  const pairs = [];
  for (const part of rawQuery.split('&')) {
    if (part === '') continue;
    const j = part.indexOf('=');
    const key = j < 0 ? part : part.slice(0, j);
    const value = j < 0 ? '' : part.slice(j + 1);
    pairs.push([encodeComponent(decodeComponent(key)), encodeComponent(decodeComponent(value))]);
  }
  pairs.sort((a, b) => compareBytes(a[0], b[0]) || compareBytes(a[1], b[1]));
  return { path, query: pairs.map(([k, v]) => `${k}=${v}`).join('&') };
}

// ---------------------------------------------------------------------------
// Step 2: build StringToSign
// ---------------------------------------------------------------------------

export function buildHmacStringToSign({ direction = 'P2S', method, requestURI, applicationId, timestamp, body }) {
  const { path, query } = splitCanonicalURI(requestURI);
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  return [
    `TC-SIGN-V1:${direction}`,   // 1 protocol tag
    method,                      // 2 method
    path,                        // 3 path
    query,                       // 4 normalized query (may be empty, the line is still present)
    applicationId,               // 5 TC-ApplicationID
    timestamp,                   // 6 TC-Timestamp
    bodyHash,                    // 7 SHA-256 of the raw body
  ].join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// Step 3: sign / compare
// ---------------------------------------------------------------------------

export function signHmac(secret, stringToSign) {
  return crypto.createHmac('sha256', secret).update(stringToSign).digest('hex');
}

/** Constant-time compare. Only 64-char lowercase hex is accepted. */
export function verifyHmac(secret, stringToSign, signature) {
  if (!/^[0-9a-f]{64}$/.test(signature || '')) return false;
  const expected = crypto.createHmac('sha256', secret).update(stringToSign).digest();
  return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), expected);
}

// ---------------------------------------------------------------------------
// Replay protection: timestamp must be 13-digit milliseconds within +/- skewSec of now
// ---------------------------------------------------------------------------

export function checkTimestamp(ts, skewSec) {
  if (!/^\d{13}$/.test(ts || '')) throw new SignError(SIGN_INVALID, 'bad timestamp');
  if (Math.abs(Date.now() - Number(ts)) > skewSec * 1000) throw new SignError(SIGN_EXPIRED, 'timestamp expired');
}

// ---------------------------------------------------------------------------
// Entry point used by the server
// ---------------------------------------------------------------------------

/**
 * Verify an inbound request. `rawBody` MUST be the bytes exactly as received
 * (do not re-serialize parsed JSON, the body hash would not match). Throws SignError.
 */
export function verifyRequest(req, rawBody, cfg) {
  const timestamp = req.headers['tc-timestamp'];
  const signature = req.headers['tc-signature'];
  const applicationId = req.headers['tc-applicationid'] || '';

  // 1. required headers + timestamp window
  if (!timestamp || !signature) throw new SignError(SIGN_INVALID, 'missing signature headers');
  checkTimestamp(timestamp, cfg.skewSec);

  // 2. our configuration must be valid, otherwise fail closed
  const signKeyChars = [...(cfg.signKey || '')].length;   // console accepts 16-64 characters
  if (signKeyChars < 16 || signKeyChars > 64) {
    throw new SignError(SERVER_ERROR, 'sign key not configured');
  }
  if (cfg.applicationId && applicationId !== cfg.applicationId) throw new SignError(SIGN_INVALID, 'application mismatch');

  // 3. rebuild StringToSign from what we received and compare
  const stringToSign = buildHmacStringToSign({
    method: req.method, requestURI: req.url, applicationId, timestamp, body: rawBody,
  });
  if (!verifyHmac(cfg.signKey, stringToSign, signature)) throw new SignError(SIGN_INVALID, 'signature mismatch');
}
