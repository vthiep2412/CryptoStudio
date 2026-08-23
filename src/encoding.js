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