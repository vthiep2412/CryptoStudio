export const algorithms = {
    encoding: [
        { id: 'base64', name: 'Base64' },
        { id: 'base32', name: 'Base32' },
        { id: 'base58', name: 'Base58' },
        { id: 'hex', name: 'Hexadecimal' },
        { id: 'binary', name: 'Binary' },
        { id: 'uri', name: 'URI Component' }
    ],
    encryption: [
        { id: 'aes-gcm', name: 'AES-GCM (Recommended)' },
        { id: 'aes', name: 'AES-CBC (Legacy)' },
        { id: 'tripledes', name: 'TripleDES' },
        { id: 'rabbit', name: 'Rabbit' },
        { id: 'rc4', name: 'RC4' },
        { id: 'xor', name: 'XOR Cipher' }
    ],
    pgp: [
        { id: 'pgp-encrypt', name: 'PGP Encrypt' },
        { id: 'pgp-decrypt', name: 'PGP Decrypt' },
        { id: 'pgp-sign', name: 'PGP Sign' },
        { id: 'pgp-verify', name: 'PGP Verify' }
    ]
};