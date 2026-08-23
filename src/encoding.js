import CryptoJS from 'crypto-js';

// Pre-instantiate encoders
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const Base32 = {
    chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    encode: function (text) {
        const bytes = encoder.encode(text);
        let bits = 0, value = 0, output = [];
        for (let i = 0; i < bytes.length; i++) {
            value = (value << 8) | bytes[i];
            bits += 8;
            while (bits >= 5) {
                output.push(this.chars[(value >>> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) output.push(this.chars[(value << (5 - bits)) & 31]);
        while ((output.length % 8) !== 0) output.push("=");
        return output.join('');
    },
    decode: function (encoded) {
        encoded = encoded.replace(/=+$/, "").toUpperCase();
        let bits = 0, value = 0, bytes = [];
        for (let i = 0; i < encoded.length; i++) {
            const val = this.chars.indexOf(encoded[i]);
            if (val === -1) throw new Error("Invalid Base32 character.");
            value = (value << 5) | val;
            bits += 5;
            if (bits >= 8) {
                bytes.push((value >>> (bits - 8)) & 255);
                bits -= 8;
            }
        }
        return decoder.decode(new Uint8Array(bytes));
    }
};

export const Base58 = {
    chars: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    encode: function (text) {
        if (!text) return "";
        const bytes = Array.from(encoder.encode(text));
        const digits = [];
        for (const byte of bytes) {
            let carry = byte;
            for (let j = 0; j < digits.length; j++) {
                carry += digits[j] << 8;
                digits[j] = carry % 58;
                carry = (carry / 58) | 0;
            }
            while (carry > 0) {
                digits.push(carry % 58);
                carry = (carry / 58) | 0;
            }
        }
        let res = digits.reverse().map(d => this.chars[d]).join("");
        for (const byte of bytes) {
            if (byte === 0) res = this.chars[0] + res;
            else break;
        }
        return res;
    },
    decode: function (encoded) {
        if (!encoded) return "";
        const bytes = [];
        for (const char of encoded) {
            let carry = this.chars.indexOf(char);
            if (carry < 0) throw new Error("Invalid Base58 character.");
            for (let j = 0; j < bytes.length; j++) {
                carry += bytes[j] * 58;
                bytes[j] = carry % 256;
                carry = (carry / 256) | 0;
            }
            while (carry > 0) {
                bytes.push(carry % 256);
                carry = (carry / 256) | 0;
            }
        }
        for (const char of encoded) {
            if (char === this.chars[0]) bytes.push(0);
            else break;
        }
        return decoder.decode(new Uint8Array(bytes.reverse()));
    }
};

// Base64URL (RFC 4648)
export const Base64URL = {
    encode: (text) => btoa(unescape(encodeURIComponent(text))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
    decode: (str) => {
        let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) b64 += '=';
        return decodeURIComponent(escape(atob(b64)));
    }
};

// Base85 / Ascii85 (btoa / atob style)
export const Base85 = {
    encode: function (text) {
        const bytes = encoder.encode(text);
        let out = '';
        for (let i = 0; i < bytes.length; i += 4) {
            const chunk = bytes.subarray(i, i + 4);
            let val = 0;
            for (let j = 0; j < 4; j++) {
                val = val * 256 + (j < chunk.length ? chunk[j] : 0);
            }
            // convert 32-bit uint to 5 base-85 chars
            const tuple = [];
            for (let j = 0; j < 5; j++) {
                tuple.unshift(String.fromCharCode((val % 85) + 33));
                val = Math.floor(val / 85);
            }
            const pad = 4 - chunk.length;
            out += tuple.slice(0, 5 - pad).join('');
        }        return `<~${out}~>`;
    },
    decode: function (str) {
        let clean = str.replace(/\s+/g, '');
        if (clean.startsWith('<~')) clean = clean.slice(2);
        if (clean.endsWith('~>')) clean = clean.slice(0, -2);

        const bytes = [];
        for (let i = 0; i < clean.length; ) {
            if (clean[i] === 'z') {
                bytes.push(0, 0, 0, 0);
                i++;
                continue;
            }
            const chunk = clean.slice(i, i + 5);
            let val = 0;
            for (let j = 0; j < 5; j++) {
                const code = j < chunk.length ? chunk.charCodeAt(j) - 33 : 84;
                if (code < 0 || code > 84) throw new Error('Invalid Base85 character.');
                val = val * 85 + code;
            }
            const pad = 5 - chunk.length;
            const fullBytes = [
                (val >>> 24) & 255,
                (val >>> 16) & 255,
                (val >>> 8) & 255,
                val & 255
            ];
            for (let j = 0; j < 4 - pad; j++) {
                bytes.push(fullBytes[j]);
            }
            i += chunk.length;
        }
        return decoder.decode(new Uint8Array(bytes));
    }
};

// Octal Encoder / Decoder
export const Octal = {
    encode: (text) => Array.from(encoder.encode(text)).map(b => b.toString(8).padStart(3, '0')).join(' '),
    decode: (text) => {
        const parts = text.trim().split(/\s+/).filter(Boolean);
        const bytes = new Uint8Array(parts.map(p => {
            if (!/^[0-7]+$/.test(p)) throw new Error('Invalid octal byte.');
            const num = parseInt(p, 8);
            if (isNaN(num) || num < 0 || num > 255) throw new Error('Invalid octal byte.');
            return num;
        }));
        return decoder.decode(bytes);
    }
};

// ROT13 / Caesar Shift
export const ROT13 = {
    encode: (text) => text.replace(/[a-zA-Z]/g, (c) => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
    }),
    decode: (text) => ROT13.encode(text) // ROT13 is symmetric
};

// HTML Entities
export const HTMLEntities = {
    encode: (text) => text.replace(/[\u00A0-\u9999<>&"']/g, (c) => `&#${c.charCodeAt(0)};`),
    decode: (text) => {
        const doc = new DOMParser().parseFromString(text, 'text/html');
        return doc.documentElement.textContent || '';
    }
};

// Morse Code Map
const MORSE_MAP = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--',
    '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
    '9': '----.', '0': '-----', ' ': '/', '/': '-..-.', '.': '.-.-.-', ',': '--..--',
    '?': '..--..', '!': '-.-.--', '@': '.--.-.'
};
const REVERSE_MORSE = Object.entries(MORSE_MAP).reduce((acc, [k, v]) => { acc[v] = k; return acc; }, {});

export const MorseCode = {
    encode: (text) => text.toUpperCase().split('').map(c => MORSE_MAP[c] || c).join(' '),
    decode: (text) => text.trim().split(/\s+/).map(m => {
        if (m === '/') return ' ';
        return REVERSE_MORSE[m] || m;
    }).join('')
};