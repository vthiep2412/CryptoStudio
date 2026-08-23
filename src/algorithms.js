export const algorithms = {
    encoding: [
        // Binary-to-Text
        { id: 'base64', name: 'Base64', group: 'Binary to Text' },
        { id: 'base64url', name: 'Base64URL (URL-Safe)', group: 'Binary to Text' },
        { id: 'base32', name: 'Base32', group: 'Binary to Text' },
        { id: 'base58', name: 'Base58', group: 'Binary to Text' },
        { id: 'base85', name: 'Base85 / Ascii85', group: 'Binary to Text' },
        { id: 'hex', name: 'Hexadecimal (Base16)', group: 'Binary to Text' },
        { id: 'binary', name: 'Binary (Base2)', group: 'Binary to Text' },
        { id: 'octal', name: 'Octal (Base8)', group: 'Binary to Text' },
        // Text & Web Formats
        { id: 'uri', name: 'URI Component', group: 'Text & Formats' },
        { id: 'html-entities', name: 'HTML Entities', group: 'Text & Formats' },
        { id: 'rot13', name: 'ROT13 / Caesar Shift', group: 'Text & Formats' },
        { id: 'morse', name: 'Morse Code', group: 'Text & Formats' }
    ],
    encryption: [
        // Modern AEAD
        { id: 'aes-gcm', name: 'AES-256-GCM', group: 'Modern AEAD' },
        { id: 'xaes-gcm', name: 'XAES-256-GCM', group: 'Modern AEAD' },
        { id: 'chacha20-poly1305', name: 'ChaCha20-Poly1305', group: 'Modern AEAD' },
        { id: 'xchacha20-poly1305', name: 'XChaCha20-Poly1305', group: 'Modern AEAD' },
        { id: 'xsalsa20-poly1305', name: 'XSalsa20-Poly1305', group: 'Modern AEAD' },
        // Modern Stream & Block
        { id: 'aes-ctr', name: 'AES-256-CTR', group: 'Stream & Block' },
        { id: 'aes', name: 'AES-256-CBC', group: 'Stream & Block' },
        { id: 'chacha20', name: 'ChaCha20', group: 'Stream & Block' },
        { id: 'salsa20', name: 'Salsa20', group: 'Stream & Block' },
        // Classical & Legacy
        { id: 'tripledes', name: 'TripleDES (3DES)', group: 'Legacy & Classical' },
        { id: 'rabbit', name: 'Rabbit', group: 'Legacy & Classical' },
        { id: 'rc4', name: 'RC4 (ARC4)', group: 'Legacy & Classical' },
        { id: 'xor', name: 'XOR Cipher', group: 'Legacy & Classical' }
    ],
    hashing: [
        // Keyed Authenticators (MAC)
        { id: 'hmac-sha256', name: 'HMAC-SHA256', group: 'Keyed MAC' },
        { id: 'hmac-sha512', name: 'HMAC-SHA512', group: 'Keyed MAC' },
        { id: 'poly1305', name: 'Poly1305 (One-Time MAC)', group: 'Keyed MAC' },
        { id: 'blake3-mac', name: 'BLAKE3-MAC', group: 'Keyed MAC' },
        // Cryptographic Hashes
        { id: 'sha256', name: 'SHA-256', group: 'Standard Hashes' },
        { id: 'sha512', name: 'SHA-512', group: 'Standard Hashes' },
        { id: 'sha3-256', name: 'SHA3-256', group: 'Standard Hashes' },
        { id: 'sha3-512', name: 'SHA3-512', group: 'Standard Hashes' },
        { id: 'blake3', name: 'BLAKE3', group: 'High-Speed Hashes' },
        { id: 'blake2s', name: 'BLAKE2s', group: 'High-Speed Hashes' },
        { id: 'blake2b', name: 'BLAKE2b', group: 'High-Speed Hashes' },
        { id: 'md5', name: 'MD5 (Legacy Checksum)', group: 'Legacy Hashes' },
        { id: 'sha1', name: 'SHA-1 (Legacy Checksum)', group: 'Legacy Hashes' }
    ],
    pgp: [
        { id: 'pgp-encrypt', name: 'PGP Encrypt', group: 'OpenPGP' },
        { id: 'pgp-decrypt', name: 'PGP Decrypt', group: 'OpenPGP' },
        { id: 'pgp-sign', name: 'PGP Sign', group: 'OpenPGP' },
        { id: 'pgp-verify', name: 'PGP Verify', group: 'OpenPGP' }
    ]
};