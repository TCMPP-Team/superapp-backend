// Decrypt the identity envelope carried in the checkUser request body.
//
//   {
//     "userId": "...",
//     "encryptedData": {
//       "algorithm":  "AEAD_AES_256_GCM",
//       "ciphertext": "base64(ciphertext || 16B tag)",
//       "nonce":      "base64(12B nonce)"
//     }
//   }
//
// Plaintext = {"openId":"...","miniAppId":"..."}, AES-256-GCM, no AAD (nil / empty are equivalent).
// The envelope lives in the body, so it is covered by the HMAC body hash.

import crypto from 'node:crypto';

// Wire-protocol identifier only; the cipher itself is standard AES-256-GCM ('aes-256-gcm' below).
export const ALGO_GCM = 'AEAD_AES_256_GCM';

export class DecryptError extends Error {}

export function decryptGcm(ciphertextB64, nonceB64, key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new DecryptError('data key must be 32 bytes');
  if (typeof ciphertextB64 !== 'string' || typeof nonceB64 !== 'string') throw new DecryptError('bad envelope');
  const sealed = Buffer.from(ciphertextB64, 'base64');
  const nonce = Buffer.from(nonceB64, 'base64');
  if (nonce.length !== 12 || sealed.length < 16) throw new DecryptError('bad envelope');
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', key, nonce);
    d.setAuthTag(sealed.subarray(sealed.length - 16));
    const plain = Buffer.concat([d.update(sealed.subarray(0, sealed.length - 16)), d.final()]);
    return plain.toString('utf8');
  } catch {
    // Single generic error: do not leak why decryption failed.
    throw new DecryptError('decrypt failed');
  }
}

/**
 * @param {object} body parsed checkUser body
 * @param {Buffer|undefined} dataEncryptKey 32-byte data key
 * @returns {{openId:string, miniAppId:string} | null} null when the body carries no encryptedData
 */
export function decryptIdentity(body, dataEncryptKey) {
  const env = body?.encryptedData;
  if (env === undefined || env === null) return null;
  if (typeof env !== 'object' || env.algorithm !== ALGO_GCM) throw new DecryptError('unsupported algorithm');
  const plain = decryptGcm(env.ciphertext, env.nonce, dataEncryptKey);
  let obj;
  try { obj = JSON.parse(plain); } catch { throw new DecryptError('bad identity json'); }
  return { openId: String(obj.openId ?? ''), miniAppId: String(obj.miniAppId ?? '') };
}
