import CryptoJS from 'crypto-js';
import { Base32, Base58, Base64URL, Base85, Octal, ROT13, HTMLEntities, MorseCode } from './encoding.js';
import { pbkdf2DeriveNative, uint8ArrayToWordArray, encryptAesGcm, decryptAesGcm, encryptAesCtr, decryptAesCtr } from './crypto-native.js';
import { encryptNobleAEAD, decryptNobleAEAD, encryptNobleStream, decryptNobleStream, computeNobleHash, computeNobleMAC } from './crypto-noble.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Generic helper to get iteration count
function getIterations(isEnhanced, level) {
    return isEnhanced ? Math.pow(10, level - 1) : 1000;
}

// Helper to encrypt with legacy ciphers using the new native PBKDF2
async function encryptLegacy(t, k, algoFn, keySize, ivSize, prefix) {
    const isEnhanced = document.getElementById('enhanceProtection')?.checked ?? false;
    const addPrefix = document.getElementById('addAlgoPrefix')?.checked ?? true;
    const lv = parseInt(document.getElementById('securityLevel')?.value) || 5;
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
        const payload = saltWordArray.toString(CryptoJS.enc.Base64) + ":" + encrypted.toString();

        if (addPrefix) {
            return `lv${lv}:${prefix}:${payload}`;
        }
        return payload;
    } else {
        const encrypted = algoFn.encrypt(t, k).toString();
        if (addPrefix) {
            return `${prefix}:${encrypted}`;
        }
        return encrypted;
    }
}

// Central resilient decryption function
async function resilientDecryption(input, passphrase, keySize, ivSize, decryptFn, prefix) {
    const clean = (str) => {
        // Remove all whitespace (newlines, spaces, tabs) which often get inserted when copying large chunks of text
        return str.replace(/\s+/g, '');
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

    let cipherPart = t;
    let encodedLv = null;

    // Check lvN:prefix: or lvN: or prefix:
    const fullMatch = t.match(new RegExp(`^lv(\\d):(?:${prefix}:)?(.+)`));
    if (fullMatch) {
        encodedLv = parseInt(fullMatch[1]);
        cipherPart = fullMatch[2];
    } else if (prefix && t.startsWith(`${prefix}:`)) {
        cipherPart = t.substring(prefix.length + 1);
    }

    const parts = cipherPart.split(':');
    if (parts.length >= 2) {
        const saltPart = parts[0];
        const rawCipher = parts.slice(1).join(':');

        const selectedLv = parseInt(document.getElementById('securityLevel')?.value) || 5;
        const levels = [];
        if (encodedLv !== null) levels.push(encodedLv);
        if (!levels.includes(selectedLv)) levels.push(selectedLv);

        for (const l of levels) {
            const res = await tryLevel(saltPart, rawCipher, l);
            if (res) return res;
        }
    }

    try {
        const rawDec = decryptFn(cipherPart, passphrase).toString(CryptoJS.enc.Utf8);
        if (rawDec) return rawDec;
    } catch (e) { }

    throw new Error("Decryption failed. Please verify your key and security level.");
}

function createCipherTransformer({ prefix, encryptFn, decryptFn, errorText }) {
    return {
        process: async (t, k) => {
            const isEnhanced = document.getElementById('enhanceProtection')?.checked ?? false;
            const addPrefix = document.getElementById('addAlgoPrefix')?.checked ?? true;
            const lv = parseInt(document.getElementById('securityLevel')?.value) || 5;
            const iters = getIterations(isEnhanced, lv);
            const cipher = await encryptFn(t, k, iters);

            if (!addPrefix) {
                return cipher;
            }
            return isEnhanced ? `lv${lv}:${prefix}:${cipher}` : `${prefix}:${cipher}`;
        },
        reverse: async (t, k) => {
            const clean = t.replace(/\s+/g, '');
            const isEnhanced = document.getElementById('enhanceProtection')?.checked ?? false;
            const selectedLv = parseInt(document.getElementById('securityLevel')?.value) || 5;

            let cipherPart = clean;
            let encodedLv = null;

            const regex = new RegExp(`^lv(\\d):${prefix}:(.+)`);
            const lvMatch = clean.match(regex);
            if (lvMatch) {
                encodedLv = parseInt(lvMatch[1]);
                cipherPart = lvMatch[2];
            } else if (clean.startsWith(`${prefix}:`)) {
                cipherPart = clean.substring(prefix.length + 1);
            } else {
                const plainLvMatch = clean.match(/^lv(\d):(.+)/);
                if (plainLvMatch) {
                    encodedLv = parseInt(plainLvMatch[1]);
                    cipherPart = plainLvMatch[2];
                }
            }

            // Build candidate iteration list
            const itersToTry = [];
            if (encodedLv !== null) {
                itersToTry.push(Math.pow(10, encodedLv - 1));
            } else {
                // Unprefixed or unannotated: try selected level enhanced, then standard 1000, then legacy 1
                itersToTry.push(Math.pow(10, selectedLv - 1));
                itersToTry.push(1000);
                itersToTry.push(1);
            }

            for (const iters of itersToTry) {
                try {
                    return await decryptFn(cipherPart, k, iters);
                } catch (e) {
                    continue;
                }
            }

            throw new Error(errorText);
        }
    };
}

export const Transformers = {
    base64: {
        process: (t) => btoa(unescape(encodeURIComponent(t))),
        reverse: (t) => {
            const clean = t.replace(/\s+/g, '');
            return decodeURIComponent(escape(atob(clean)));
        }
    },
    base64url: {
        process: (t) => Base64URL.encode(t),
        reverse: (t) => Base64URL.decode(t)
    },
    base32: {
        process: (t) => Base32.encode(t),
        reverse: (t) => Base32.decode(t)
    },
    base58: {
        process: (t) => Base58.encode(t),
        reverse: (t) => Base58.decode(t)
    },
    base85: {
        process: (t) => Base85.encode(t),
        reverse: (t) => Base85.decode(t)
    },
    hex: {
        process: (t) => Array.from(encoder.encode(t)).map(b => b.toString(16).padStart(2, '0')).join(''),
        reverse: (t) => {
            const clean = t.replace(/\s+/g, '');
            if (clean.length === 0) return '';
            if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
                throw new Error("Invalid hex string.");
            }
            const bytes = new Uint8Array(clean.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
            return decoder.decode(bytes);
        }
    },
    binary: {
        process: (t) => Array.from(encoder.encode(t)).map(b => b.toString(2).padStart(8, '0')).join(' '),
        reverse: (t) => {
            const parts = t.trim().split(/\s+/).filter(Boolean);
            if (parts.length === 0) return '';
            for (const p of parts) {
                if (!/^[01]{8}$/.test(p)) throw new Error("Invalid binary string.");
            }
            const bytes = new Uint8Array(parts.map(p => parseInt(p, 2)));
            return decoder.decode(bytes);
        }
    },
    octal: {
        process: (t) => Octal.encode(t),
        reverse: (t) => Octal.decode(t)
    },
    uri: {
        process: (t) => encodeURIComponent(t),
        reverse: (t) => decodeURIComponent(t)
    },
    html: {
        process: (t) => HTMLEntities.encode(t),
        reverse: (t) => HTMLEntities.decode(t)
    },
    rot13: {
        process: (t) => ROT13.encode(t),
        reverse: (t) => ROT13.decode(t)
    },
    morse: {
        process: (t) => MorseCode.encode(t),
        reverse: (t) => MorseCode.decode(t)
    },

    // ENCRYPTION - Modern AEAD
    'aes-gcm': createCipherTransformer({
        prefix: 'gcm',
        encryptFn: (t, k, iters) => encryptAesGcm(t, k, iters),
        decryptFn: (c, k, iters) => decryptAesGcm(c, k, iters),
        errorText: 'AES-GCM decryption failed. Check password and format.'
    }),
    'chacha20-poly1305': createCipherTransformer({
        prefix: 'c20p',
        encryptFn: (t, k, iters) => encryptNobleAEAD(t, k, 'chacha20-poly1305', iters),
        decryptFn: (c, k, iters) => decryptNobleAEAD(c, k, 'chacha20-poly1305', iters),
        errorText: 'ChaCha20-Poly1305 decryption failed. Check password.'
    }),
    'xchacha20-poly1305': createCipherTransformer({
        prefix: 'xc20p',
        encryptFn: (t, k, iters) => encryptNobleAEAD(t, k, 'xchacha20-poly1305', iters),
        decryptFn: (c, k, iters) => decryptNobleAEAD(c, k, 'xchacha20-poly1305', iters),
        errorText: 'XChaCha20-Poly1305 decryption failed. Check password.'
    }),
    'xsalsa20-poly1305': createCipherTransformer({
        prefix: 'xsalsa',
        encryptFn: (t, k, iters) => encryptNobleAEAD(t, k, 'xsalsa20-poly1305', iters),
        decryptFn: (c, k, iters) => decryptNobleAEAD(c, k, 'xsalsa20-poly1305', iters),
        errorText: 'XSalsa20-Poly1305 decryption failed. Check password.'
    }),

    // ENCRYPTION - Stream & Block
    'aes-ctr': createCipherTransformer({
        prefix: 'ctr',
        encryptFn: (t, k, iters) => encryptAesCtr(t, k, iters),
        decryptFn: (c, k, iters) => decryptAesCtr(c, k, iters),
        errorText: 'AES-CTR decryption failed. Check password and format.'
    }),
    chacha20: createCipherTransformer({
        prefix: 'c20',
        encryptFn: (t, k, iters) => encryptNobleStream(t, k, 'chacha20', iters),
        decryptFn: (c, k, iters) => decryptNobleStream(c, k, 'chacha20', iters),
        errorText: 'ChaCha20 decryption failed.'
    }),
    salsa20: createCipherTransformer({
        prefix: 'salsa',
        encryptFn: (t, k, iters) => encryptNobleStream(t, k, 'salsa20', iters),
        decryptFn: (c, k, iters) => decryptNobleStream(c, k, 'salsa20', iters),
        errorText: 'Salsa20 decryption failed.'
    }),
    aes: {
        process: (t, k) => encryptLegacy(t, k, CryptoJS.AES, 32, 16, 'aes'),
        reverse: (t, k) => resilientDecryption(t, k, 32, 16, CryptoJS.AES.decrypt, 'aes')
    },
    tripledes: {
        process: (t, k) => encryptLegacy(t, k, CryptoJS.TripleDES, 24, 8, '3des'),
        reverse: (t, k) => resilientDecryption(t, k, 24, 8, CryptoJS.TripleDES.decrypt, '3des')
    },
    rabbit: {
        process: (t, k) => encryptLegacy(t, k, CryptoJS.Rabbit, 16, 8, 'rabbit'),
        reverse: (t, k) => resilientDecryption(t, k, 16, 8, CryptoJS.Rabbit.decrypt, 'rabbit')
    },
    rc4: {
        process: (t, k) => encryptLegacy(t, k, CryptoJS.RC4, 16, 0, 'rc4'),
        reverse: (t, k) => resilientDecryption(t, k, 16, 0, CryptoJS.RC4.decrypt, 'rc4')
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
            const cleanT = t.replace(/\s+/g, '');
            const raw = atob(cleanT);
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

    // HASHING & HMAC
    'hmac-sha256': {
        process: (t, k) => computeNobleMAC(t, k, 'hmac-sha256'),
        reverse: (t, k) => computeNobleMAC(t, k, 'hmac-sha256')
    },
    'hmac-sha512': {
        process: (t, k) => computeNobleMAC(t, k, 'hmac-sha512'),
        reverse: (t, k) => computeNobleMAC(t, k, 'hmac-sha512')
    },
    'poly1305': {
        process: (t, k) => computeNobleMAC(t, k, 'poly1305'),
        reverse: (t, k) => computeNobleMAC(t, k, 'poly1305')
    },
    'blake3-mac': {
        process: (t, k) => computeNobleMAC(t, k, 'blake3-mac'),
        reverse: (t, k) => computeNobleMAC(t, k, 'blake3-mac')
    },
    'sha256': {
        process: (t) => CryptoJS.SHA256(t).toString(),
        reverse: (t) => CryptoJS.SHA256(t).toString()
    },
    'sha512': {
        process: (t) => CryptoJS.SHA512(t).toString(),
        reverse: (t) => CryptoJS.SHA512(t).toString()
    },
    'sha3-256': {
        process: (t) => computeNobleHash(t, 'sha3-256'),
        reverse: (t) => computeNobleHash(t, 'sha3-256')
    },
    'sha3-512': {
        process: (t) => computeNobleHash(t, 'sha3-512'),
        reverse: (t) => computeNobleHash(t, 'sha3-512')
    },
    'blake3': {
        process: (t) => computeNobleHash(t, 'blake3'),
        reverse: (t) => computeNobleHash(t, 'blake3')
    },
    'blake2s': {
        process: (t) => computeNobleHash(t, 'blake2s'),
        reverse: (t) => computeNobleHash(t, 'blake2s')
    },
    'blake2b': {
        process: (t) => computeNobleHash(t, 'blake2b'),
        reverse: (t) => computeNobleHash(t, 'blake2b')
    },
    'md5': {
        process: (t) => CryptoJS.MD5(t).toString(),
        reverse: (t) => CryptoJS.MD5(t).toString()
    },
    'sha1': {
        process: (t) => CryptoJS.SHA1(t).toString(),
        reverse: (t) => CryptoJS.SHA1(t).toString()
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
            const sigEntry = verificationResult.signatures[0];
            try {
                await sigEntry.verified;
                const keyId = sigEntry.keyID ? sigEntry.keyID.toHex().toUpperCase() : 'UNKNOWN';
                return `--- SIGNATURE VALID ---\nSigner Key ID: ${keyId}\n\nContent:\n${message.getText()}`;
            } catch (e) {
                throw new Error("Signature verification failed: " + e.message);
            }
        }
    }
};