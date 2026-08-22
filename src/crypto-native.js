import CryptoJS from 'crypto-js';

// Web Crypto PBKDF2 implementation to replace CryptoJS
export async function pbkdf2DeriveNative(passphrase, saltBytes, keySize, ivSize, iterations) {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(passphrase);

    // Import password as a key for derivation
    const baseKey = await crypto.subtle.importKey(
        'raw',
        passwordBytes,
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
    );

    // Derive bits using SHA-256
    const totalBytes = keySize + ivSize;
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: saltBytes,
            iterations: iterations,
            hash: 'SHA-256'
        },
        baseKey,
        totalBytes * 8 // subtle wants bits
    );

    return new Uint8Array(derivedBits);
}

// Helper to convert ArrayBuffer to Base64
export function bufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// Helper to convert Base64 to ArrayBuffer
export function base64ToBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

// AES-GCM Encryption using Native Web Crypto API
export async function encryptAesGcm(text, passphrase, iterations) {
    const encoder = new TextEncoder();

    // Generate salt and IV
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Derive key
    const passwordKey = await crypto.subtle.importKey(
        "raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]
    );

    const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: iterations, hash: "SHA-256" },
        passwordKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
    );

    // Encrypt
    const ciphertextBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoder.encode(text)
    );

    // Format: salt:iv:ciphertext (all base64)
    return `${bufferToBase64(salt)}:${bufferToBase64(iv)}:${bufferToBase64(ciphertextBuffer)}`;
}

// AES-GCM Decryption using Native Web Crypto API
export async function decryptAesGcm(formattedString, passphrase, iterations) {
    const parts = formattedString.split(':');
    if (parts.length !== 3) throw new Error("Invalid AES-GCM format.");

    const salt = base64ToBuffer(parts[0]);
    const iv = base64ToBuffer(parts[1]);
    const ciphertext = base64ToBuffer(parts[2]);

    const encoder = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
        "raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]
    );

    const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: iterations, hash: "SHA-256" },
        passwordKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
    );

    const decryptedBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(iv) },
        key,
        ciphertext
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
}

// Convert Uint8Array to CryptoJS WordArray
export function uint8ArrayToWordArray(u8Array) {
    const words = [];
    for (let i = 0; i < u8Array.length; i += 4) {
        words.push(
            (u8Array[i] << 24) |
            (u8Array[i + 1] << 16) |
            (u8Array[i + 2] << 8) |
            (u8Array[i + 3])
        );
    }
    return CryptoJS.lib.WordArray.create(words, u8Array.length);
}