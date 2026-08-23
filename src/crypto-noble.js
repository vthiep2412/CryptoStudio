import { chacha20poly1305, xchacha20poly1305, chacha20 } from '@noble/ciphers/chacha.js';
import { salsa20, xsalsa20poly1305 } from '@noble/ciphers/salsa.js';
import { poly1305 } from '@noble/ciphers/_poly1305.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { blake2s, blake2b } from '@noble/hashes/blake2.js';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { pbkdf2DeriveNative, bufferToBase64, base64ToBuffer } from './crypto-native.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function getSecureRandom(len) {
    const bytes = new Uint8Array(len);
    crypto.getRandomValues(bytes);
    return bytes;
}

// Universal AEAD Encrypt with PBKDF2 Key Derivation
export async function encryptNobleAEAD(text, passphrase, cipherType, iterations) {
    const salt = getSecureRandom(16);
    const key = await pbkdf2DeriveNative(passphrase, salt, 32, 0, iterations);

    let nonceLen = 12;
    if (cipherType === 'xchacha20-poly1305' || cipherType === 'xsalsa20-poly1305') {
        nonceLen = 24;
    }
    const nonce = getSecureRandom(nonceLen);
    const data = encoder.encode(text);

    let ciphertext;
    if (cipherType === 'chacha20-poly1305') {
        const cipher = chacha20poly1305(key, nonce);
        ciphertext = cipher.encrypt(data);
    } else if (cipherType === 'xchacha20-poly1305') {
        const cipher = xchacha20poly1305(key, nonce);
        ciphertext = cipher.encrypt(data);
    } else if (cipherType === 'xsalsa20-poly1305') {
        const cipher = xsalsa20poly1305(key, nonce);
        ciphertext = cipher.encrypt(data);
    }

    return `${bufferToBase64(salt)}:${bufferToBase64(nonce)}:${bufferToBase64(ciphertext)}`;
}

// Universal AEAD Decrypt with PBKDF2 Key Derivation
export async function decryptNobleAEAD(formattedString, passphrase, cipherType, iterations) {
    const clean = formattedString.replace(/\s+/g, '');
    const parts = clean.split(':');
    if (parts.length !== 3) throw new Error(`Invalid ${cipherType} format.`);

    const salt = new Uint8Array(base64ToBuffer(parts[0]));
    const nonce = new Uint8Array(base64ToBuffer(parts[1]));
    const ciphertext = new Uint8Array(base64ToBuffer(parts[2]));

    const key = await pbkdf2DeriveNative(passphrase, salt, 32, 0, iterations);
    let decrypted;

    if (cipherType === 'chacha20-poly1305') {
        const cipher = chacha20poly1305(key, nonce);
        decrypted = cipher.decrypt(ciphertext);
    } else if (cipherType === 'xchacha20-poly1305') {
        const cipher = xchacha20poly1305(key, nonce);
        decrypted = cipher.decrypt(ciphertext);
    } else if (cipherType === 'xsalsa20-poly1305') {
        const cipher = xsalsa20poly1305(key, nonce);
        decrypted = cipher.decrypt(ciphertext);
    }

    return decoder.decode(decrypted);
}

// Stream Cipher (ChaCha20 / Salsa20 raw)
export async function encryptNobleStream(text, passphrase, cipherType, iterations) {
    const salt = getSecureRandom(16);
    const nonceLen = cipherType === 'chacha20' ? 12 : 8;
    const nonce = getSecureRandom(nonceLen);
    const key = await pbkdf2DeriveNative(passphrase, salt, 32, 0, iterations);
    const data = encoder.encode(text);

    let ciphertext;
    if (cipherType === 'chacha20') {
        ciphertext = chacha20(key, nonce, data);
    } else {
        ciphertext = salsa20(key, nonce, data);
    }

    return `${bufferToBase64(salt)}:${bufferToBase64(nonce)}:${bufferToBase64(ciphertext)}`;
}

export async function decryptNobleStream(formattedString, passphrase, cipherType, iterations) {
    const clean = formattedString.replace(/\s+/g, '');
    const parts = clean.split(':');
    if (parts.length !== 3) throw new Error(`Invalid ${cipherType} format.`);

    const salt = new Uint8Array(base64ToBuffer(parts[0]));
    const nonce = new Uint8Array(base64ToBuffer(parts[1]));
    const ciphertext = new Uint8Array(base64ToBuffer(parts[2]));
    const key = await pbkdf2DeriveNative(passphrase, salt, 32, 0, iterations);

    let decrypted;
    if (cipherType === 'chacha20') {
        decrypted = chacha20(key, nonce, ciphertext);
    } else {
        decrypted = salsa20(key, nonce, ciphertext);
    }

    return decoder.decode(decrypted);
}

// Hashes & Keyed MACs Helpers
export function computeNobleHash(text, algo) {
    const data = encoder.encode(text);
    let hashBytes;
    switch (algo) {
        case 'blake3': hashBytes = blake3(data); break;
        case 'blake2s': hashBytes = blake2s(data); break;
        case 'blake2b': hashBytes = blake2b(data); break;
        case 'sha3-256': hashBytes = sha3_256(data); break;
        case 'sha3-512': hashBytes = sha3_512(data); break;
        default: throw new Error(`Unsupported hash algorithm: ${algo}`);
    }
    return Array.from(hashBytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function computeNobleMAC(text, keyString, algo) {
    const data = encoder.encode(text);
    const key = encoder.encode(keyString);
    let macBytes;

    if (algo === 'poly1305') {
        const polyKey = hmac(sha256, key, data).subarray(0, 32);
        macBytes = poly1305(data, polyKey);
    } else if (algo === 'blake3-mac') {
        const paddedKey = key.length === 32 ? key : sha256(key);
        macBytes = blake3(data, { key: paddedKey });
    } else if (algo === 'hmac-sha256') {
        macBytes = hmac(sha256, key, data);
    } else if (algo === 'hmac-sha512') {
        macBytes = hmac(sha512, key, data);
    }

    return Array.from(macBytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
