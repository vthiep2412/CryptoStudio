import CryptoJS from 'crypto-js';
import { Base32, Base58 } from './encoding.js';
import { pbkdf2DeriveNative, uint8ArrayToWordArray, encryptAesGcm, decryptAesGcm } from './crypto-native.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Generic helper to get iteration count
function getIterations(isEnhanced, level) {
    return isEnhanced ? Math.pow(10, level - 1) : 1;
}

// Helper to encrypt with legacy ciphers using the new native PBKDF2
async function encryptLegacy(t, k, algoFn, keySize, ivSize) {
    const isEnhanced = document.getElementById('enhanceProtection').checked;
    const lv = parseInt(document.getElementById('securityLevel').value) || 5;
    const iters = getIterations(isEnhanced, lv);

    // Generate salt using native crypto
    const saltBytes = new Uint8Array(128 / 8);
    crypto.getRandomValues(saltBytes);
    const saltWordArray = uint8ArrayToWordArray(saltBytes);

    if (isEnhanced) {
        const derivedBytes = await pbkdf2DeriveNative(k, saltBytes, keySize, ivSize, iters);
        const derivedWords = uint8ArrayToWordArray(derivedBytes);

        const key = CryptoJS.lib.WordArray.create(derivedWords.words.slice(0, keySize / 4), keySize);
        const iv = ivSize > 0 ? CryptoJS.lib.WordArray.create(derivedWords.words.slice(keySize / 4, (keySize + ivSize) / 4), ivSize) : null;

        const options = iv ? { iv: iv } : {};
        const encrypted = algoFn.encrypt(t, key, options);
        return `lv${lv}:` + saltWordArray.toString(CryptoJS.enc.Base64) + ":" + encrypted.toString();
    } else {
        return algoFn.encrypt(t, k).toString();
    }
}

// Central resilient decryption function
async function resilientDecryption(input, passphrase, keySize, ivSize, decryptFn) {
    const clean = (str) => {
        return str.trim()
            .replace(/=/g, '')
            .replace(/^[:]+|[:]+$/g, '')
            .replace(/:+/g, ':');
    };

    const t = clean(input);
    if (!t) throw new Error("Decryption failed. Please verify your input.");

    async function tryLevel(saltB64, ciphertext, lv) {
        try {
            const iters = Math.pow(10, lv - 1);
            const saltWordArray = CryptoJS.enc.Base64.parse(saltB64);

            // Convert WordArray back to Uint8Array for native PBKDF2
            const saltBytes = new Uint8Array(saltWordArray.sigBytes);
            for(let i=0; i<saltWordArray.sigBytes; i++) {
                saltBytes[i] = (saltWordArray.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            }

            const derivedBytes = await pbkdf2DeriveNative(passphrase, saltBytes, keySize, ivSize, iters);
            const derivedWords = uint8ArrayToWordArray(derivedBytes);

            const key = CryptoJS.lib.WordArray.create(derivedWords.words.slice(0, keySize / 4), keySize);
            const iv = (ivSize > 0) ? CryptoJS.lib.WordArray.create(derivedWords.words.slice(keySize / 4, (keySize + ivSize) / 4), ivSize) : null;
            const options = iv ? { iv: iv } : {};
            const dec = decryptFn(ciphertext, key, options).toString(CryptoJS.enc.Utf8);
            return dec || null;
        } catch (e) { return null; }
    }

    const lvMatch = t.match(/^lv(\d):/);
    if (lvMatch) {
        const lv = parseInt(lvMatch[1]);
        const parts = t.substring(lvMatch[0].length).split(':');
        if (parts.length >= 2) {
            const res = await tryLevel(parts[0], parts[1], lv);
            if (res) return res;
        }
    }

    const parts = t.split(':');
    let saltPart = null, cipherPart = null;
    if (lvMatch && parts.length >= 3) {
        saltPart = parts[1];
        cipherPart = parts[2];
    } else if (!lvMatch && parts.length >= 2) {
        saltPart = parts[0];
        cipherPart = parts[1];
    }

    if (saltPart && cipherPart) {
        const selectedLv = parseInt(document.getElementById('securityLevel').value) || 5;
        const levels = [selectedLv, 1, 2, 3, 4, 5, 6, 7];
        const seen = new Set();
        for (const l of levels) {
            if (seen.has(l)) continue;
            seen.add(l);
            const res = await tryLevel(saltPart, cipherPart, l);
            if (res) return res;
        }
    }

    try {
        const rawDec = decryptFn(input.trim(), passphrase).toString(CryptoJS.enc.Utf8);
        if (rawDec) return rawDec;
    } catch (e) { }

    throw new Error("Decryption failed. Please verify your key and security level.");
}

export const Transformers = {
    // ENCODING
    base64: {
        process: (t) => btoa(unescape(encodeURIComponent(t))),
        reverse: (t) => decodeURIComponent(escape(atob(t)))
    },
    base32: {
        process: (t) => Base32.encode(t),
        reverse: (t) => Base32.decode(t)
    },
    base58: {
        process: (t) => Base58.encode(t),
        reverse: (t) => Base58.decode(t)
    },
    hex: {
        process: (t) => Array.from(encoder.encode(t)).map(b => b.toString(16).padStart(2, '0')).join(''),
        reverse: (t) => {
            t = t.replace(/\s+/g, '');
            if (t.length % 2 !== 0) throw new Error("Invalid hex length.");
            const bytes = new Uint8Array(t.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
            return decoder.decode(bytes);
        }
    },
    binary: {
        process: (t) => Array.from(encoder.encode(t)).map(b => b.toString(2).padStart(8, '0')).join(' '),
        reverse: (t) => {
            t = t.replace(/\s+/g, '');
            if (t.length % 8 !== 0) throw new Error("Invalid binary length.");
            const bytes = new Uint8Array(t.match(/.{1,8}/g).map(byte => parseInt(byte, 2)));
            return decoder.decode(bytes);
        }
    },
    uri: {
        process: (t) => encodeURIComponent(t),
        reverse: (t) => decodeURIComponent(t)
    },

    // ENCRYPTION
    'aes-gcm': {
        process: async (t, k) => {
            const isEnhanced = document.getElementById('enhanceProtection').checked;
            const lv = parseInt(document.getElementById('securityLevel').value) || 5;
            const iters = getIterations(isEnhanced, lv);
            const cipher = await encryptAesGcm(t, k, iters);
            return isEnhanced ? `lv${lv}:gcm:${cipher}` : `gcm:${cipher}`;
        },
        reverse: async (t, k) => {
            const clean = t.trim();
            const isEnhanced = document.getElementById('enhanceProtection').checked;
            let lv = parseInt(document.getElementById('securityLevel').value) || 5;

            let cipherPart = clean;
            const lvMatch = clean.match(/^lv(\d):gcm:(.+)/);
            if (lvMatch) {
                lv = parseInt(lvMatch[1]);
                cipherPart = lvMatch[2];
            } else if (clean.startsWith('gcm:')) {
                cipherPart = clean.substring(4);
            }

            const iters = getIterations(isEnhanced || lvMatch !== null, lv);
            try {
                return await decryptAesGcm(cipherPart, k, iters);
            } catch(e) {
                 // Try brute-forcing levels if decryption failed
                 const levels = [lv, 1, 2, 3, 4, 5, 6, 7];
                 for (const l of levels) {
                     if (l === lv) continue;
                     try {
                         const currentIters = Math.pow(10, l - 1);
                         return await decryptAesGcm(cipherPart, k, currentIters);
                     } catch(err) {
                         continue;
                     }
                 }
                 throw new Error("AES-GCM decryption failed. Check password and format.");
            }
        }
    },
    aes: {
        process: (t, k) => encryptLegacy(t, k, CryptoJS.AES, 32, 16),
        reverse: (t, k) => resilientDecryption(t, k, 32, 16, CryptoJS.AES.decrypt)
    },
    tripledes: {
        process: (t, k) => encryptLegacy(t, k, CryptoJS.TripleDES, 24, 8),
        reverse: (t, k) => resilientDecryption(t, k, 24, 8, CryptoJS.TripleDES.decrypt)
    },
    rabbit: {
        process: (t, k) => encryptLegacy(t, k, CryptoJS.Rabbit, 16, 8),
        reverse: (t, k) => resilientDecryption(t, k, 16, 8, CryptoJS.Rabbit.decrypt)
    },
    rc4: {
        process: (t, k) => encryptLegacy(t, k, CryptoJS.RC4, 16, 0),
        reverse: (t, k) => resilientDecryption(t, k, 16, 0, CryptoJS.RC4.decrypt)
    },
    xor: {
        process: (t, k) => {
            const tBytes = encoder.encode(t);
            const kBytes = encoder.encode(k);
            let res = new Uint8Array(tBytes.length);
            for (let i = 0; i < tBytes.length; i++) {
                res[i] = tBytes[i] ^ kBytes[i % kBytes.length];
            }

            const parts = [];
            const chunkSize = 0x8000;
            for (let i = 0; i < res.length; i += chunkSize) {
                parts.push(String.fromCharCode.apply(null, res.subarray(i, i + chunkSize)));
            }
            return btoa(parts.join(''));
        },
        reverse: (t, k) => {
            const raw = atob(t);
            const tBytes = new Uint8Array(raw.length);
            for (let i = 0; i < raw.length; i++) tBytes[i] = raw.charCodeAt(i);
            const kBytes = encoder.encode(k);
            let res = new Uint8Array(tBytes.length);
            for (let i = 0; i < tBytes.length; i++) {
                res[i] = tBytes[i] ^ kBytes[i % kBytes.length];
            }
            return decoder.decode(res);
        }
    },

    // OPENPGP
    'pgp-encrypt': {
        process: async (t, k) => {
            const openpgp = await import('openpgp');
            const publicKey = await openpgp.readKey({ armoredKey: k });
            return await openpgp.encrypt({
                message: await openpgp.createMessage({ text: t }),
                encryptionKeys: publicKey
            });
        }
    },
    'pgp-decrypt': {
        process: async (t, k, p) => {
            const openpgp = await import('openpgp');
            const privateKey = await openpgp.readPrivateKey({ armoredKey: k });
            const unlockedKey = await openpgp.decryptKey({ privateKey, passphrase: p });
            const message = await openpgp.readMessage({ armoredMessage: t });
            const { data: decrypted } = await openpgp.decrypt({
                message,
                decryptionKeys: unlockedKey
            });
            return decrypted;
        }
    },
    'pgp-sign': {
        process: async (t, k, p) => {
            const openpgp = await import('openpgp');
            const privateKey = await openpgp.readPrivateKey({ armoredKey: k });
            const unlockedKey = await openpgp.decryptKey({ privateKey, passphrase: p });
            return await openpgp.sign({
                message: await openpgp.createMessage({ text: t }),
                signingKeys: unlockedKey
            });
        }
    },
    'pgp-verify': {
        process: async (t, k) => {
            const openpgp = await import('openpgp');
            const publicKey = await openpgp.readKey({ armoredKey: k });
            const message = await openpgp.readCleartextMessage({ cleartextMessage: t });
            const verificationResult = await openpgp.verify({
                message,
                verificationKeys: publicKey
            });
            if (!verificationResult.signatures || verificationResult.signatures.length === 0) {
                throw new Error("No signatures found in the provided text.");
            }
            const { verified, signature } = verificationResult.signatures[0];
            try {
                await verified;
                return `--- SIGNATURE VALID ---\nFingerprint: ${signature.toString().substring(0, 16).toUpperCase()}\n\nContent:\n${message.getText()}`;
            } catch (e) {
                throw new Error("Signature verification failed: " + e.message);
            }
        }
    }
};