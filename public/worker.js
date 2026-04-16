// CryptoStudio Background Worker - PBKDF2 Hardening
try {
    importScripts('https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js');
} catch (e) {
    self.postMessage({ error: 'Failed to load CryptoJS: ' + e.message });
}

self.onmessage = function(e) {
    if (typeof CryptoJS === 'undefined') {
        self.postMessage({ error: 'CryptoJS is not loaded in worker' });
        return;
    }
    const { password, saltHex, keySize, ivSize, iterations } = e.data;
    try {
        const salt = CryptoJS.enc.Hex.parse(saltHex);
        const derived = CryptoJS.PBKDF2(password, salt, {
            keySize: (keySize + ivSize) / 4,
            iterations: iterations,
            hasher: CryptoJS.algo.SHA256
        });
        self.postMessage({ derivedHex: derived.toString(CryptoJS.enc.Hex) });
    } catch (err) {
        self.postMessage({ error: 'PBKDF2 derivation failed: ' + err.message });
    }
};
