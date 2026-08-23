import { algorithms } from './algorithms.js';
import { Transformers } from './transformers.js';
import { initializeCustomDropdowns, createRipple } from './utils.js';
import { toggleTheme, initTheme } from './theme.js';
import DOMPurify from 'dompurify';

let currentCategory = 'encoding';
let currentPgpAlgo = 'pgp-encrypt';

// DOM Elements - Using getters to ensure they are available after DOM load
const els = {
    get btnEncoding() { return document.getElementById('btnEncoding'); },
    get btnEncryption() { return document.getElementById('btnEncryption'); },
    get btnHashing() { return document.getElementById('btnHashing'); },
    get btnPGP() { return document.getElementById('btnPGP'); },
    get actionArea() { return document.getElementById('actionArea'); },
    get pgpActionArea() { return document.getElementById('pgpActionArea'); },
    get pgpPillBg() { return document.getElementById('pgpPillBg'); },
    get labelProcess() { return document.getElementById('labelProcess'); },
    get labelReverse() { return document.getElementById('labelReverse'); },
    get algorithmSelect() { return document.getElementById('algorithmSelect'); },
    get algoSelectContainer() { return document.getElementById('algoSelectContainer'); },
    get keyContainer() { return document.getElementById('keyContainer'); },
    get cryptoKeyLabel() { return document.querySelector('label[for="cryptoKey"]'); },
    get pgpPassContainer() { return document.getElementById('pgpPassContainer'); },
    get genKeyLink() { return document.getElementById('genKeyLink'); },
    get inputText() { return document.getElementById('inputText'); },
    get cryptoKey() { return document.getElementById('cryptoKey'); },
    get receivedMac() { return document.getElementById('receivedMac'); },
    get receivedMacContainer() { return document.getElementById('receivedMacContainer'); },
    get pgpPassphraseInput() { return document.getElementById('pgpPassphrase'); },
    get outputArea() { return document.getElementById('outputArea'); },
    get recoveryArea() { return document.getElementById('recoveryArea'); },
    get toastMsg() { return document.getElementById('toastMsg'); },
    get radioActions() { return document.getElementsByName('action'); },
    get statusText() { return document.getElementById('statusText'); }
};

const statusPhrases = [
    "Distilling logic",
    "Processing data",
    "Inhaling data",
    "Creating entropy",
    "Sifting chaos",
    "Refining noise",
    "Folding logic",
    "Parsing shadows"
];

let statusAnimationInterval = null;
let phraseCycleInterval = null;

function setAnimatedStatus(target, onComplete) {
    if (statusAnimationInterval) clearInterval(statusAnimationInterval);
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#$@&";
    const current = els.statusText.innerText || "";
    const maxLength = Math.max(current.length, target.length);
    let iteration = 0;

    statusAnimationInterval = setInterval(() => {
        let display = "";
        let complete = true;

        for (let i = 0; i < maxLength; i++) {
            const stagger = i * 2;
            const lockTime = stagger + 8;

            if (iteration >= lockTime) {
                display += target[i] || "";
            } else if (iteration >= stagger) {
                const randomValues = new Uint32Array(1);
                crypto.getRandomValues(randomValues);
                display += chars[randomValues[0] % chars.length];
                complete = false;
            } else {
                display += current[i] || "";
                complete = false;
            }
        }

        els.statusText.innerText = display;
        if (complete) {
            clearInterval(statusAnimationInterval);
            els.statusText.innerText = target;
            if (onComplete) onComplete();
        }
        iteration++;
    }, 40);
}

function startStatusCycling() {
    if (phraseCycleInterval) clearTimeout(phraseCycleInterval);

    const update = () => {
        const randomValues = new Uint32Array(1);
        crypto.getRandomValues(randomValues);
        const phrase = statusPhrases[randomValues[0] % statusPhrases.length];
        setAnimatedStatus(phrase, () => {
            phraseCycleInterval = setTimeout(update, 1000);
        });
    };

    update();
}

function stopStatusCycling(finalTarget) {
    if (phraseCycleInterval) {
        clearTimeout(phraseCycleInterval);
        phraseCycleInterval = null;
    }
    setAnimatedStatus(finalTarget);
}

function debounce(func, wait) {
    let timeout;
    return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

const debouncedExecute = debounce(executeTransformation, 300);

export function init() {
    populateSelect();
    addEventListeners();
    setCategory('encoding', false);
}

export function setCategory(cat, save = true) {
    currentCategory = cat;
    if (save) localStorage.setItem('activeCategory', cat);
    const pill = document.getElementById('pillBg');

    [els.btnEncoding, els.btnEncryption, els.btnHashing, els.btnPGP].forEach(b => b?.classList.remove('active'));

    if (cat === 'encoding') {
        pill.style.setProperty('--pill-translate', '0%');
        els.btnEncoding.classList.add('active');
        els.labelProcess.textContent = "Encode";
        els.labelReverse.textContent = "Decode";
        els.keyContainer.classList.add('hidden');
        els.keyContainer.classList.remove('flex');
        els.genKeyLink.classList.add('hidden');
        els.algoSelectContainer.classList.remove('hidden');
        els.actionArea.classList.remove('hidden');
        els.pgpActionArea.classList.add('hidden');
    } else if (cat === 'encryption') {
        pill.style.setProperty('--pill-translate', '100%');
        els.btnEncryption.classList.add('active');
        els.labelProcess.textContent = "Encrypt";
        els.labelReverse.textContent = "Decrypt";
        els.keyContainer.classList.remove('hidden');
        els.keyContainer.classList.add('flex');
        els.genKeyLink.classList.add('hidden');
        els.algoSelectContainer.classList.remove('hidden');
        els.actionArea.classList.remove('hidden');
        els.pgpActionArea.classList.add('hidden');
    } else if (cat === 'hashing') {
        pill.style.setProperty('--pill-translate', '200%');
        els.btnHashing.classList.add('active');
        els.labelProcess.textContent = "Hash / Sign";
        els.labelReverse.textContent = "Verify";
        els.algoSelectContainer.classList.remove('hidden');
        els.actionArea.classList.remove('hidden');
        els.pgpActionArea.classList.add('hidden');
    } else {
        pill.style.setProperty('--pill-translate', '300%');
        els.btnPGP.classList.add('active');
        els.keyContainer.classList.remove('hidden');
        els.keyContainer.classList.add('flex');
        els.genKeyLink.classList.remove('hidden');
        els.algoSelectContainer.classList.add('hidden');
        els.actionArea.classList.add('hidden');
        els.pgpActionArea.classList.remove('hidden');
        els.pgpActionArea.classList.add('flex');
    }

    populateSelect();
    updatePGPFields();
    executeTransformation();
    initializeCustomDropdowns();
}

export function setPgpAction(algo, idx, save = true) {
    currentPgpAlgo = algo;
    if (save) {
        localStorage.setItem('activePgpAlgo', algo);
        localStorage.setItem('activePgpIdx', idx);
    }
    const pill = document.getElementById('pgpPillBg');
    const btns = document.querySelectorAll('.pgp-switch-btn');

    pill.style.setProperty('--pill-translate', `${idx * 100}%`);

    btns.forEach(b => b.classList.remove('active'));
    btns[idx].classList.add('active');

    updatePGPFields();
    executeTransformation();
}

function updatePGPFields() {
    const protection = document.getElementById('protectionControls');
    if (currentCategory === 'pgp') {
        const algo = currentPgpAlgo;
        els.pgpActionArea.classList.remove('hidden');
        els.pgpActionArea.classList.add('flex', 'col-span-full');
        els.algoSelectContainer.classList.add('hidden');
        els.receivedMacContainer?.classList.add('hidden');
        els.receivedMacContainer?.classList.remove('flex');
        if (protection) protection.classList.add('hidden');

        els.keyContainer.classList.remove('hidden');
        els.keyContainer.classList.add('flex');
        els.genKeyLink.classList.remove('hidden');

        if (algo === 'pgp-decrypt' || algo === 'pgp-sign') {
            els.pgpPassContainer.classList.remove('hidden');
            els.pgpPassContainer.classList.add('flex');
            els.cryptoKeyLabel.textContent = "Your Private Key";
            els.cryptoKey.placeholder = "Paste your Armored Private Key here...";
        } else {
            els.pgpPassContainer.classList.add('hidden');
            els.pgpPassContainer.classList.remove('flex');
            els.cryptoKeyLabel.textContent = algo === 'pgp-encrypt' ? "Recipient's Public Key" : "Sender's Public Key";
            els.cryptoKey.placeholder = "Paste Armored Public Key here...";
        }
    } else if (currentCategory === 'hashing') {
        els.pgpActionArea.classList.add('hidden');
        els.pgpActionArea.classList.remove('flex', 'col-span-full');
        els.pgpPassContainer.classList.add('hidden');
        els.pgpPassContainer.classList.remove('flex');
        els.genKeyLink.classList.add('hidden');
        if (protection) protection.classList.add('hidden');

        const algo = els.algorithmSelect.value;
        const isMAC = algo.startsWith('hmac') || algo === 'poly1305' || algo === 'blake3-mac';
        const action = getAction();

        if (isMAC) {
            els.actionArea.classList.remove('hidden');
            els.algoSelectContainer.classList.remove('col-span-full', 'sm:col-start-2');
            els.keyContainer.classList.remove('hidden');
            els.keyContainer.classList.add('flex');
            els.cryptoKeyLabel.textContent = "Secret Key / HMAC Key";
            els.cryptoKey.placeholder = "Enter your secret key...";

            if (action === 'reverse') {
                els.receivedMacContainer?.classList.remove('hidden');
                els.receivedMacContainer?.classList.add('flex');
            } else {
                els.receivedMacContainer?.classList.add('hidden');
                els.receivedMacContainer?.classList.remove('flex');
            }
        } else {
            // Non-MAC standard hash: Reset radio action to 'process'
            const processRadio = document.querySelector('input[name="action"][value="process"]');
            if (processRadio) processRadio.checked = true;

            els.actionArea.classList.add('hidden');
            els.algoSelectContainer.classList.remove('col-span-full');
            els.algoSelectContainer.classList.add('sm:col-start-2');
            els.keyContainer.classList.add('hidden');
            els.keyContainer.classList.remove('flex');
            els.receivedMacContainer?.classList.add('hidden');
            els.receivedMacContainer?.classList.remove('flex');
        }
    } else {
        els.algoSelectContainer.classList.remove('col-span-full', 'sm:col-start-2');
        els.pgpActionArea.classList.add('hidden');
        els.pgpActionArea.classList.remove('flex');
        els.pgpPassContainer.classList.add('hidden');
        els.pgpPassContainer.classList.remove('flex');
        els.receivedMacContainer?.classList.add('hidden');
        els.receivedMacContainer?.classList.remove('flex');
        els.cryptoKeyLabel.textContent = "Secret Key / Password";
        els.cryptoKey.placeholder = "Enter your secret key or password...";
        els.actionArea.classList.remove('hidden');

        if (protection) {
            const algo = els.algorithmSelect.value;
            const nonHardened = ['xor', 'tripledes', 'rabbit', 'rc4'];
            if (currentCategory === 'encryption' && !nonHardened.includes(algo)) {
                protection.classList.remove('hidden');
                protection.classList.add('flex');
            } else {
                protection.classList.add('hidden');
            }
        }
    }

    // Prefix toggle switch visibility (Encryption tab, all algorithms except XOR, and in Encrypt mode)
    const prefixContainer = document.getElementById('prefixToggleContainer');
    if (prefixContainer) {
        const algo = els.algorithmSelect.value;
        const action = getAction();
        if (currentCategory === 'encryption' && algo !== 'xor' && action === 'process') {
            prefixContainer.classList.remove('hidden');
            prefixContainer.classList.add('flex');
        } else {
            prefixContainer.classList.add('hidden');
            prefixContainer.classList.remove('flex');
        }
    }
}

function populateSelect() {
    els.algorithmSelect.textContent = '';
    const list = algorithms[currentCategory] || [];
    list.forEach(algo => {
        const opt = document.createElement('option');
        opt.value = algo.id;
        opt.textContent = algo.name;
        if (algo.group) opt.dataset.group = algo.group;
        els.algorithmSelect.appendChild(opt);
    });
}

function addEventListeners() {
    els.inputText.addEventListener('input', debouncedExecute);
    els.cryptoKey.addEventListener('input', debouncedExecute);
    els.receivedMac?.addEventListener('input', debouncedExecute);
    els.pgpPassphraseInput.addEventListener('input', debouncedExecute);
    document.getElementById('addAlgoPrefix')?.addEventListener('change', debouncedExecute);
    els.algorithmSelect.addEventListener('change', () => {
        updatePGPFields();
        executeTransformation();
    });
    els.radioActions.forEach(radio => {
        radio.addEventListener('change', () => {
            updatePGPFields();
            executeTransformation();
        });
    });
}

function getAction() {
    for (const radio of els.radioActions) {
        if (radio.checked) return radio.value;
    }
    return 'process';
}

export function clearInput() {
    els.inputText.value = '';
    if (els.statusText) {
        els.statusText.className = 'text-xs text-slate-500 uppercase font-black tracking-widest';
        stopStatusCycling('Idle');
    }
    executeTransformation();
}

export function copyOutput() {
    const textToCopy = els.outputArea.innerText;
    if (!textToCopy) return;

    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(textToCopy).then(() => {
            els.toastMsg.classList.remove('opacity-0');
            setTimeout(() => els.toastMsg.classList.add('opacity-0'), 2000);
        }).catch(err => {
            console.error('Clipboard API failed', err);
        });
    } else {
        const textArea = document.createElement("textarea");
        textArea.value = textToCopy;
        textArea.style.position = "fixed";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            document.execCommand('copy');
            els.toastMsg.classList.remove('opacity-0');
            setTimeout(() => els.toastMsg.classList.add('opacity-0'), 2000);
        } catch (err) {
            console.error('Copy failed', err);
        }
        document.body.removeChild(textArea);
    }
}

let lastRequestId = 0;
export async function executeTransformation() {
    const currentRequestId = ++lastRequestId;
    const text = els.inputText.value;
    let algo = currentCategory === 'pgp' ? currentPgpAlgo : els.algorithmSelect.value;
    const action = getAction();
    const key = els.cryptoKey.value;
    const pgpPass = els.pgpPassphraseInput.value.trim();
    els.recoveryArea.classList.add('hidden');
    els.recoveryArea.classList.remove('flex');
    els.recoveryArea.textContent = '';

    if (!text) {
        els.outputArea.textContent = 'Output will appear here...';
        els.outputArea.className = 'bg-[var(--bg-app)] border border-[var(--border-card)] rounded-lg p-4 flex-grow min-h-[150px] md:min-h-[300px] overflow-auto custom-scrollbar font-mono text-xs text-gray-600 italic break-all whitespace-pre-wrap';
        if (els.statusText) els.statusText.innerText = '';
        return;
    }

    const isMAC = algo.startsWith('hmac') || algo === 'poly1305' || algo === 'blake3-mac';
    const requiresKey = currentCategory === 'encryption' || currentCategory === 'pgp' || (currentCategory === 'hashing' && isMAC);

    if (requiresKey && !key) {
        els.outputArea.textContent = `Please provide a ${currentCategory === 'pgp' ? 'PGP Key' : 'Secret Key'}.`;
        els.outputArea.className = 'bg-[var(--bg-app)] border border-[var(--border-card)] rounded-lg p-4 flex-grow min-h-[150px] md:min-h-[300px] overflow-auto custom-scrollbar font-mono text-xs text-red-400 break-all whitespace-pre-wrap';
        if (els.statusText) els.statusText.innerText = '';
        return;
    }

    // reset output class on success/process
    els.outputArea.className = 'bg-[var(--bg-app)] border border-[var(--border-card)] rounded-lg p-4 flex-grow min-h-[150px] md:min-h-[300px] overflow-auto custom-scrollbar font-mono text-sm text-[var(--text-secondary)] break-all whitespace-pre-wrap';

    if (els.statusText) {
        els.statusText.className = 'text-xs text-emerald-500 font-bold uppercase tracking-widest';
        startStatusCycling();
    }

    try {
        const transformer = Transformers[algo];
        if (!transformer) throw new Error("Algorithm not implemented.");

        let result = "";
        if (currentCategory === 'pgp') {
            result = await transformer.process(text, key, pgpPass);
        } else if (currentCategory === 'hashing' && action === 'reverse') {
            const received = els.receivedMac?.value.trim();
            if (!received) {
                els.outputArea.textContent = 'Please paste the Received MAC / Signature above to verify.';
                els.outputArea.className = 'bg-[var(--bg-app)] border border-[var(--border-card)] rounded-lg p-4 flex-grow min-h-[150px] md:min-h-[300px] overflow-auto custom-scrollbar font-mono text-xs text-yellow-500 italic break-all whitespace-pre-wrap';
                if (els.statusText) {
                    els.statusText.className = 'text-xs text-yellow-500 font-bold uppercase tracking-widest';
                    stopStatusCycling('Awaiting MAC');
                }
                return;
            }

            const computed = await transformer.process(text, key);
            const isValid = computed.toLowerCase() === received.toLowerCase().replace(/\s+/g, '');

            if (isValid) {
                result = `✓ AUTHENTIC / VALID MAC\n\nThe message has not been altered and matches the provided Secret Key.\n\nComputed MAC: ${computed}\nReceived MAC: ${received}`;
            } else {
                result = `✗ INVALID / TAMPERED MAC\n\nThe provided MAC does NOT match the computed signature for this message and key.\n\nComputed MAC: ${computed}\nReceived MAC: ${received}`;
            }
        } else {
            if (action === 'process') {
                result = await transformer.process(text, key);
            } else {
                result = await transformer.reverse(text, key);
            }
        }

        if (currentRequestId !== lastRequestId) return;

        els.outputArea.textContent = result;
        if (els.statusText) {
            els.statusText.className = 'text-xs text-emerald-500 font-bold uppercase tracking-widest';
            stopStatusCycling('Ready');
        }

    } catch (err) {
        if (currentRequestId !== lastRequestId) return;

        els.outputArea.textContent = '';
        const errorSpan = document.createElement('span');
        errorSpan.className = 'text-red-400 flex items-start gap-2 font-mono text-xs';

        const svgHTML = '<svg class="w-4 h-4 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>';

        errorSpan.innerHTML = DOMPurify.sanitize(svgHTML);

        const messageSpan = document.createElement('span');

        if (err.message.includes("Misformed armored text")) {
            messageSpan.textContent = 'Error: Misformed armor. You need to have the BEGIN/END wrapper lines.';
            errorSpan.appendChild(messageSpan);
            els.outputArea.appendChild(errorSpan);

            els.recoveryArea.textContent = '';
            const recoveryBtn = document.createElement('button');
            recoveryBtn.className = 'w-fit px-4 py-2 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 text-xs font-medium rounded-lg border border-emerald-500/30 transition-all uppercase tracking-wider';
            recoveryBtn.textContent = 'Add wrapper for this action';
            recoveryBtn.dataset.algo = algo;
            recoveryBtn.addEventListener('click', (e) => {
                addPgpWrapper(e.currentTarget.dataset.algo);
            });

            els.recoveryArea.appendChild(recoveryBtn);
            els.recoveryArea.classList.remove('hidden');
            els.recoveryArea.classList.add('flex');
        } else {
            messageSpan.textContent = 'Error: ' + err.message;
            errorSpan.appendChild(messageSpan);
            els.outputArea.appendChild(errorSpan);

            // Auto-detect format from input prefix if it doesn't match the selected algorithm
            if (currentCategory === 'encryption') {
                const cleanInput = text.replace(/\s+/g, '');
                const prefixMap = {
                    'c20p': { id: 'chacha20-poly1305', name: 'ChaCha20-Poly1305' },
                    'xc20p': { id: 'xchacha20-poly1305', name: 'XChaCha20-Poly1305' },
                    'xsalsa': { id: 'xsalsa20-poly1305', name: 'XSalsa20-Poly1305' },
                    'gcm': { id: 'aes-gcm', name: 'AES-256-GCM' },
                    'ctr': { id: 'aes-ctr', name: 'AES-256-CTR' },
                    'c20': { id: 'chacha20', name: 'ChaCha20' },
                    'salsa': { id: 'salsa20', name: 'Salsa20' },
                    'aes': { id: 'aes', name: 'AES-256-CBC' },
                    '3des': { id: 'tripledes', name: 'TripleDES (3DES)' },
                    'rabbit': { id: 'rabbit', name: 'Rabbit' },
                    'rc4': { id: 'rc4', name: 'RC4 (ARC4)' }
                };

                let detected = null;
                const prefixMatch = cleanInput.match(/^(?:lv\d:)?([a-z0-9]+):/);
                if (prefixMatch && prefixMap[prefixMatch[1]]) {
                    detected = prefixMap[prefixMatch[1]];
                }

                if (detected && detected.id !== algo) {
                    els.recoveryArea.textContent = '';
                    const warningBox = document.createElement('div');
                    warningBox.className = 'w-full p-2 bg-amber-500/10 border border-amber-500/30 rounded-xl flex items-center justify-between gap-2 text-amber-400 font-mono';

                    warningBox.innerHTML = DOMPurify.sanitize(`
                        <div class="flex items-center gap-2">
                            <svg class="w-7 h-7 text-amber-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                            </svg>
                            <div class="flex flex-col justify-center">
                                <span class="text-xs font-bold text-amber-300 tracking-wide leading-snug">Algorithm Mismatch</span>
                                <span class="text-xs text-amber-400/90 font-sans leading-tight">This ciphertext was encrypted with <strong>${detected.name}</strong></span>
                            </div>
                        </div>
                    `);

                    const switchBtn = document.createElement('button');
                    switchBtn.className = 'px-3 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 rounded-lg border border-amber-500/40 text-[10px] font-bold uppercase tracking-wider text-center leading-tight whitespace-pre-line transition-all shrink-0 active:scale-95';
                    switchBtn.textContent = `Switch to\n${detected.name}`;
                    switchBtn.onclick = () => {
                        els.algorithmSelect.value = detected.id;
                        els.algorithmSelect.dispatchEvent(new Event('change'));
                    };

                    warningBox.appendChild(switchBtn);
                    els.recoveryArea.appendChild(warningBox);
                    els.recoveryArea.classList.remove('hidden');
                    els.recoveryArea.classList.add('flex');
                }
            }
        }
        if (els.statusText) {
            els.statusText.className = 'text-[10px] text-red-500 font-bold uppercase tracking-widest';
            stopStatusCycling('Error');
        }
    }
}

export async function addPgpWrapper(algo) {
    const el = els.cryptoKey;
    const key = el.value.trim();
    if (!key) return;
    if (key.includes('-----BEGIN PGP')) return;
    let wrapped = "";
    if (algo === 'pgp-decrypt' || algo === 'pgp-sign') {
        wrapped = `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n${key}\n-----END PGP PRIVATE KEY BLOCK-----`;
    } else {
        wrapped = `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n${key}\n-----END PGP PUBLIC KEY BLOCK-----`;
    }

    el.value = wrapped;
    executeTransformation();
}

export function togglePgpPass() {
    const btn = document.getElementById('pgpPassToggle');
    const input = els.pgpPassphraseInput;
    const type = input.type === 'password' ? 'text' : 'password';
    input.type = type;

    const eye = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/><circle cx="12" cy="12" r="3"/></svg>`;
    const eyeOff = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-5 h-5"><path d="m15 18-.722-3.25"/><path d="M2 8a10.645 10.645 0 0 0 20 0"/><path d="m20 15-1.726-2.05"/><path d="m4 15 1.726-2.05"/><path d="m9 18 .722-3.25"/></svg>`;

    btn.innerHTML = DOMPurify.sanitize(type === 'password' ? eye : eyeOff);

    const label = document.querySelector('label[for="pgpPassphrase"]');
    if (label) label.innerText = `PGP PASSPHRASE (${type === 'password' ? 'HIDDEN' : 'VISIBLE'})`;
    btn.setAttribute('aria-pressed', type === 'text');

    const svg = btn.querySelector('svg');
    if (svg) {
        svg.classList.add('animate-icon');
        setTimeout(() => svg.classList.remove('animate-icon'), 300);
    }
}

export function adjustLevel(delta) {
    const input = document.getElementById('securityLevel');
    let val = parseInt(input.value) + delta;
    if (val < 1) val = 1;
    if (val > 7) val = 7;
    syncLevel(val);
}

export function syncLevel(val) {
    const level = parseInt(val);
    document.getElementById('securityLevel').value = level;
    document.getElementById('securitySlider').value = level;
    document.getElementById('securityLevelDisplay').textContent = level;
    updateLevelSpecs();
}

export function toggleSecurityLevel() {
    const isEnhanced = document.getElementById('enhanceProtection').checked;
    const display = document.getElementById('levelDisplay');
    const slider = document.getElementById('levelSliderContainer');

    if (isEnhanced) {
        display.classList.remove('hidden');
        display.classList.add('flex');
        slider.classList.remove('hidden');
        slider.classList.add('flex');
        updateLevelSpecs();
    } else {
        display.classList.remove('flex');
        display.classList.add('hidden');
        slider.classList.remove('flex');
        slider.classList.add('hidden');
    }
    executeTransformation();
}

function updateLevelSpecs() {
    const lv = parseInt(document.getElementById('securityLevel').value);
    const specs = document.getElementById('levelSpecs');

    const contentMap = {
        1: "(lvl: 1) INSECURE: Extreme brute-force risk!",
        2: "(lvl: 2) WEAK: Minimal work factor. For non-sensitive data.",
        3: "(lvl: 3) NOT RECOMMENDED: Low work factor.",
        4: "(lvl: 4) Hardened: ~100ms. Common industry standard.",
        5: "(lvl: 5) CryptoStudio Standard: ~250ms. Balanced protection.",
        6: "(lvl: 6) NIST Web Standard: ~1s. Professional grade.",
        7: "(lvl: 7) Military Grade: 2s+. Isolated, zero brute-force risk."
    };

    specs.textContent = contentMap[lv] || `Standard Iterations`;

    if (lv <= 3) {
        specs.classList.add('text-red-500', 'font-black');
        specs.classList.remove('text-slate-500');
    } else {
        specs.classList.remove('text-red-500', 'font-black');
        specs.classList.add('text-slate-500');
    }

    executeTransformation();
}

document.addEventListener('DOMContentLoaded', () => {
    initTheme();

    // Bind functions to window so inline HTML onclicks still work
    window.setCategory = setCategory;
    window.setPgpAction = setPgpAction;
    window.clearInput = clearInput;
    window.copyOutput = copyOutput;
    window.togglePgpPass = togglePgpPass;
    window.adjustLevel = adjustLevel;
    window.syncLevel = syncLevel;
    window.toggleSecurityLevel = toggleSecurityLevel;
    window.toggleTheme = toggleTheme;

    init();

    // Restore category from localStorage with defensive validation
    const savedCat = localStorage.getItem('activeCategory');
    if (savedCat && Object.keys(algorithms).includes(savedCat)) {
        setCategory(savedCat, false);
    } else {
        setCategory('encoding', false);
    }

    // Restore PGP state with strict canonical pair validation
    const savedPgpAlgo = localStorage.getItem('activePgpAlgo');
    const savedPgpIdx = localStorage.getItem('activePgpIdx');
    const expectedPgpPairs = {
        'pgp-encrypt': '0',
        'pgp-decrypt': '1',
        'pgp-sign': '2',
        'pgp-verify': '3'
    };

    if (savedPgpAlgo && savedPgpIdx !== null && expectedPgpPairs[savedPgpAlgo] === savedPgpIdx) {
        setPgpAction(savedPgpAlgo, parseInt(savedPgpIdx, 10), false);
    } else {
        localStorage.removeItem('activePgpIdx');
        localStorage.removeItem('activePgpAlgo');
    }
});