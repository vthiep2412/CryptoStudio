import { toggleTheme, initTheme } from './theme.js';
import * as zip from '@zip.js/zip.js';
import DOMPurify from 'dompurify';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
let currentAlgo = 'ecc';
let isPassphraseValid = false;

const ui = {};
let inputs = {};

function initDom() {
    Object.assign(ui, {
        passphrase: document.getElementById('passphrase'),
        strengthBar: document.getElementById('strengthBar'),
        strengthText: document.getElementById('strengthText'),
        generateBtn: document.getElementById('generateBtn'),
        resultSection: document.getElementById('resultSection'),
        publicKeyArea: document.getElementById('publicKeyArea'),
        privateKeyArea: document.getElementById('privateKeyArea'),
        overlay: document.getElementById('overlay'),
        downloadBtn: document.getElementById('downloadBtn'),
        statusBadge: document.getElementById('statusBadge'),
        overlaySubtext: document.getElementById('overlaySubtext'),
        togglePass: document.getElementById('togglePass'),
        genPassBtn: document.getElementById('genPassBtn'),
        displayPass: document.getElementById('displayPass'),
        packageInfo: document.getElementById('packageInfo')
    });

    Object.assign(inputs, {
        name: document.getElementById('userName'),
        email: document.getElementById('userEmail')
    });
}

const icons = {
    eye: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/><circle cx="12" cy="12" r="3"/></svg>`,
    eyeOff: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><path d="m15 18-.722-3.25"/><path d="M2 8a10.645 10.645 0 0 0 20 0"/><path d="m20 15-1.726-2.05"/><path d="m4 15 1.726-2.05"/><path d="m9 18 .722-3.25"/></svg>`
};

function setupListeners() {
    ui.togglePass.addEventListener('click', () => {
        const type = ui.passphrase.type === 'password' ? 'text' : 'password';
        ui.passphrase.type = type;
        ui.togglePass.innerHTML = DOMPurify.sanitize(type === 'password' ? icons.eye : icons.eyeOff);

        const label = document.querySelector('label[for="passphrase"]');
        if (label) label.innerText = `PASSPHRASE (${type === 'password' ? 'HIDDEN' : 'VISIBLE'})`;
        ui.togglePass.setAttribute('aria-pressed', type === 'text');

        const svg = ui.togglePass.querySelector('svg');
        if (svg) {
            svg.classList.add('animate-icon');
            setTimeout(() => svg.classList.remove('animate-icon'), 300);
        }
    });

    ui.genPassBtn.addEventListener('click', () => {
        const chars = "abcdefghijklmnopqrstuvwxyz";
        const uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const symbols = "@#$%&";
        const nums = "0123456789";
        const all = chars + uppers + symbols + nums;

        let pass = [];
        for (let i = 0; i < 3; i++) pass.push(uppers[getSecureInt(uppers.length)]);
        for (let i = 0; i < 3; i++) pass.push(symbols[getSecureInt(symbols.length)]);
        for (let i = 0; i < 3; i++) pass.push(chars[getSecureInt(chars.length)]);
        for (let i = 0; i < 3; i++) pass.push(nums[getSecureInt(nums.length)]);

        while (pass.length < 16) pass.push(all[getSecureInt(all.length)]);

        const secureShuffle = (array) => {
            for (let i = array.length - 1; i > 0; i--) {
                const j = getSecureInt(i + 1);
                [array[i], array[j]] = [array[j], array[i]];
            }
            return array;
        };

        let result = "";
        let attempts = 0;
        do {
            result = secureShuffle([...pass]).join('');
            attempts++;
        } while (!validateNumbers(result) && attempts < 10);

        ui.passphrase.value = result;
        ui.passphrase.type = 'text';
        ui.togglePass.innerHTML = DOMPurify.sanitize(icons.eyeOff);

        const label = document.querySelector('label[for="passphrase"]');
        if (label) label.innerText = `PASSPHRASE (VISIBLE)`;
        ui.togglePass.setAttribute('aria-pressed', 'true');

        const svg = ui.togglePass.querySelector('svg');
        if (svg) {
            svg.classList.add('animate-icon');
            setTimeout(() => svg.classList.remove('animate-icon'), 300);
        }

        ui.strengthBar.style.width = '100%';
        ui.passphrase.dispatchEvent(new Event('input'));
    });

    inputs.name.addEventListener('input', updateGenerateState);
    inputs.email.addEventListener('input', () => {
        const isValid = EMAIL_REGEX.test(inputs.email.value);
        if (inputs.email.value && !isValid) {
            inputs.email.classList.add('focus:ring-red-500', 'border-red-500/50');
            inputs.email.classList.remove('focus:ring-emerald-500', 'border-[var(--border-card)]');
        } else {
            inputs.email.classList.remove('focus:ring-red-500', 'border-red-500/50');
            inputs.email.classList.add('focus:ring-emerald-500', 'border-[var(--border-card)]');
        }
        updateGenerateState();
    });

    ui.passphrase.addEventListener('input', () => {
        const val = ui.passphrase.value;

        if (!val) {
            ui.strengthBar.style.width = '0%';
            ui.strengthBar.className = 'h-full bg-[var(--bg-card-alt)] transition-all duration-500';
            ui.strengthText.innerText = '';
            document.querySelectorAll('[data-req]').forEach(el => {
                el.classList.replace('text-emerald-400', 'text-[var(--text-dim)]');
                el.querySelector('div').classList.replace('bg-emerald-500', 'bg-[var(--bg-card-alt)]');
            });
            isPassphraseValid = false;
            updateGenerateState();
            return;
        }

        const checks = {
            len: val.length >= 8,
            upper: (val.match(/[A-Z]/g) || []).length >= 2,
            lower: /[a-z]/.test(val),
            symbol: (val.match(/[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/g) || []).length >= 2,
            pattern: validateNumbers(val)
        };

        let points = 0;
        for (const key in checks) {
            const el = document.querySelector(`[data-req="${key}"]`);
            if (checks[key]) {
                el.classList.replace('text-[var(--text-dim)]', 'text-emerald-400');
                el.querySelector('div').classList.replace('bg-[var(--bg-card-alt)]', 'bg-emerald-500');
                points++;
            } else {
                el.classList.replace('text-emerald-400', 'text-[var(--text-dim)]');
                el.querySelector('div').classList.replace('bg-emerald-500', 'bg-[var(--bg-card-alt)]');
            }
        }

        const percent = (points / 5) * 100;
        ui.strengthBar.style.width = `${percent}%`;

        if (points < 3) {
            ui.strengthBar.className = 'h-full bg-red-500 transition-all duration-500';
            ui.strengthText.innerText = 'Weak';
            ui.strengthText.className = 'text-[10px] text-red-500 font-bold uppercase';
        } else if (points < 5) {
            ui.strengthBar.className = 'h-full bg-yellow-500 transition-all duration-500';
            ui.strengthText.innerText = 'Moderate';
            ui.strengthText.className = 'text-[10px] text-yellow-500 font-bold uppercase';
        } else {
            ui.strengthBar.className = 'h-full bg-emerald-500 transition-all duration-500';
            ui.strengthText.innerText = 'Strong';
            ui.strengthText.className = 'text-[10px] text-emerald-500 font-bold uppercase';
        }

        isPassphraseValid = (points === 5);
        updateGenerateState();
    });
}


function getSecureInt(max) {
    const array = new Uint32Array(1);
    const threshold = Math.floor(0x100000000 / max) * max;
    let r;
    do {
        window.crypto.getRandomValues(array);
        r = array[0];
    } while (r >= threshold);
    return r % max;
}

function validateNumbers(str) {
    const nums = str.match(/\d/g);
    if (!nums) return true;

    const numStr = nums.join('');

    if (/(\d)\1\1/.test(numStr)) return false;

    for (let i = 0; i < numStr.length - 2; i++) {
        const a = parseInt(numStr[i]);
        const b = parseInt(numStr[i + 1]);
        const c = parseInt(numStr[i + 2]);
        if (b === a + 1 && c === b + 1) return false;
        if (b === a - 1 && c === b - 1) return false;
    }

    return true;
}

export function setAlgo(type) {
    currentAlgo = type;
    document.querySelectorAll('.algo-btn').forEach(btn => {
        btn.classList.remove('border-emerald-500/30', 'bg-emerald-500/10', 'text-emerald-400');
        btn.classList.add('border-[var(--border-card)]', 'bg-[var(--bg-app)]', 'text-[var(--text-dim)]');
    });
    const active = document.getElementById(`algo-${type}`);
    active.classList.add('border-emerald-500/30', 'bg-emerald-500/10', 'text-emerald-400');
    active.classList.remove('border-[var(--border-card)]', 'bg-[var(--bg-app)]', 'text-[var(--text-dim)]');
}

function updateGenerateState() {
    const isNameValid = inputs.name.value.trim().length > 0;
    const isEmailValid = EMAIL_REGEX.test(inputs.email.value);

    if (isPassphraseValid && isNameValid && isEmailValid) {
        ui.generateBtn.disabled = false;
        ui.generateBtn.classList.replace('bg-[var(--bg-card-alt)]', 'bg-emerald-600');
        ui.generateBtn.classList.replace('text-[var(--text-dim)]', 'text-white');
        ui.generateBtn.classList.replace('cursor-not-allowed', 'cursor-pointer');
        ui.generateBtn.classList.add('hover:bg-emerald-500', 'shadow-lg', 'shadow-emerald-900/20');
        ui.generateBtn.innerText = 'GENERATE KEY PAIR';
    } else {
        ui.generateBtn.disabled = true;
        ui.generateBtn.className = 'w-full py-3 bg-[var(--bg-card-alt)] text-[var(--text-dim)] font-bold rounded-xl transition-all cursor-not-allowed';
        ui.generateBtn.innerText = 'WAITING FOR VALID INPUT...';
    }
}

export async function generateKeyPair() {
    const name = document.getElementById('userName').value || 'CryptoStudio User';
    const email = document.getElementById('userEmail').value || 'user@cryptostudio.local';
    const passphrase = ui.passphrase.value;

    ui.overlay.classList.remove('hidden');
    ui.overlay.classList.add('flex');
    ui.overlaySubtext.innerText = currentAlgo.includes('rsa') ? 'Generating RSA keys can take a moment...' : 'Computing ECC keys...';

    try {
        const openpgp = await import('openpgp');

        const options = {
            userIDs: [{ name, email }],
            passphrase,
            format: 'armored'
        };

        if (currentAlgo === 'ecc') {
            options.type = 'ecc';
            options.curve = 'curve25519';
        } else {
            options.type = 'rsa';
            options.rsaBits = currentAlgo === 'rsa-2048' ? 2048 : 4096;
        }

        await new Promise(r => setTimeout(r, 100));

        const key = await openpgp.generateKey(options);

        ui.publicKeyArea.innerText = key.publicKey;
        ui.privateKeyArea.innerText = key.privateKey;
        ui.displayPass.innerText = '(Your PGP Passphrase)';

        ui.resultSection.classList.remove('opacity-50', 'grayscale');
        ui.downloadBtn.disabled = false;
        ui.statusBadge.classList.remove('hidden');
        ui.packageInfo.classList.remove('hidden');

    } catch (err) {
        alert('Generation failed: ' + err.message);
    } finally {
        ui.overlay.classList.replace('flex', 'hidden');
    }
}

export async function copyKey(type, event) {
    const el = type === 'pub' ? ui.publicKeyArea : ui.privateKeyArea;
    const text = el.innerText;
    if (!text) return;

    const btn = event?.target;
    const original = btn?.innerText;
    try {
        await navigator.clipboard.writeText(text);
        if (btn) {
            btn.innerText = 'Copied!';
            setTimeout(() => btn.innerText = original, 2000);
        }
    } catch (err) {
        if (btn) {
            btn.innerText = 'Failed';
            setTimeout(() => btn.innerText = original, 2000);
        }
    }
}

export async function downloadKeys() {
    const pub = ui.publicKeyArea.innerText;
    const priv = ui.privateKeyArea.innerText;
    const pass = ui.passphrase.value;

    if (!pub || !priv) return;

    if (!pass) {
        alert('A passphrase is required to protect the ZIP archive.');
        return;
    }

    ui.downloadBtn.disabled = true;
    ui.downloadBtn.innerText = 'PACKAGING...';

    try {
        const zipWriter = new zip.ZipWriter(new zip.BlobWriter("application/zip"));

        const addOptions = { password: pass, encryptionMethod: "aes" };

        await zipWriter.add("public_key.asc", new zip.TextReader(pub), addOptions);
        await zipWriter.add("private_key.asc", new zip.TextReader(priv), addOptions);

        await zipWriter.add(`SECURITY_NOTE.txt`, new zip.TextReader(`CRYPTOSTUDIO PGP BUNDLE\n\n- Files are encrypted using AES-256.\n- PASS: Use your PGP passphrase.`), addOptions);

        const blob = await zipWriter.close();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'CryptoStudioPGP.zip';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

    } catch (err) {
        alert('Zipping failed: ' + err.message);
    } finally {
        ui.downloadBtn.disabled = false;
        ui.downloadBtn.innerText = 'DOWNLOAD AS .ZIP';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initDom();
    setupListeners();
    updateGenerateState();

    // Bind global fns for inline handlers
    window.setAlgo = setAlgo;
    window.generateKeyPair = generateKeyPair;
    window.copyKey = copyKey;
    window.downloadKeys = downloadKeys;
    window.toggleTheme = toggleTheme;
});