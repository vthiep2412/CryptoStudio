export function createRipple(e, parent) {
    const rect = parent.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const size = Math.max(rect.width, rect.height) * 2;

    const dim = document.createElement('div');
    dim.className = 'spread-ripple ripple-dim animate-ripple';
    dim.style.width = dim.style.height = `${size}px`;
    dim.style.left = `${x - size/2}px`;
    dim.style.top = `${y - size/2}px`;
    parent.appendChild(dim);

    setTimeout(() => {
        const clear = document.createElement('div');
        clear.className = 'spread-ripple ripple-clear animate-ripple';
        clear.style.width = clear.style.height = `${size}px`;
        clear.style.left = `${x - size/2}px`;
        clear.style.top = `${y - size/2}px`;
        parent.appendChild(clear);

        setTimeout(() => {
            dim.remove();
            clear.remove();
        }, 1000);
    }, 100);
}

import DOMPurify from 'dompurify';

export function initializeCustomDropdowns() {
    const selects = document.querySelectorAll('select:not(.custom-init)');
    selects.forEach(select => {
        const container = document.createElement('div');
        container.className = 'dropdown-container';

        const trigger = document.createElement('div');
        trigger.className = 'dropdown-trigger';
        trigger.tabIndex = 0;

        const label = document.createElement('span');
        label.innerText = select.options[select.selectedIndex]?.text || 'Select...';

        const arrow = document.createElement('div');
        arrow.className = 'dropdown-arrow';
        arrow.innerHTML = DOMPurify.sanitize(`<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M19 9l-7 7-7-7" /></svg>`);

        trigger.appendChild(label);
        trigger.appendChild(arrow);

        const optionsList = document.createElement('div');
        optionsList.className = 'dropdown-options custom-scrollbar';

        const syncOptions = () => {
            optionsList.textContent = '';
            let currentGroup = null;

            Array.from(select.options).forEach((opt, idx) => {
                const groupName = opt.dataset.group || opt.parentElement?.label;
                if (groupName && groupName !== currentGroup) {
                    currentGroup = groupName;
                    const header = document.createElement('div');
                    header.className = 'dropdown-group-header';
                    header.innerText = groupName;
                    optionsList.appendChild(header);
                }

                const optionEl = document.createElement('div');
                optionEl.className = 'dropdown-option' + (idx === select.selectedIndex ? ' selected' : '');
                optionEl.innerText = opt.text;
                optionEl.onclick = (e) => {
                    e.stopPropagation();
                    select.selectedIndex = idx;
                    select.dispatchEvent(new Event('change'));
                    label.innerText = opt.text;
                    toggleDropdown(false);
                };
                optionsList.appendChild(optionEl);
            });
        };

        const toggleDropdown = (show) => {
            if (show) {
                syncOptions();
                trigger.classList.add('open');
                optionsList.classList.add('show');
                const selectedEl = optionsList.querySelector('.dropdown-option.selected');
                if (selectedEl) {
                    requestAnimationFrame(() => {
                        optionsList.scrollTop =
                            selectedEl.offsetTop - (optionsList.clientHeight - selectedEl.offsetHeight) / 2;
                    });
                }            } else {
                trigger.classList.remove('open');
                optionsList.classList.remove('show');
            }
        };

        trigger.onclick = (e) => {
            const isOpen = optionsList.classList.contains('show');
            document.querySelectorAll('.dropdown-options').forEach(el => el.classList.remove('show'));
            document.querySelectorAll('.dropdown-trigger').forEach(el => el.classList.remove('open'));
            toggleDropdown(!isOpen);
            createRipple(e, trigger);
        };

        if (select._observer) select._observer.disconnect();
        const updateLabel = () => {
            label.innerText = select.options[select.selectedIndex]?.text || 'Select...';
        };
        const observer = new MutationObserver(updateLabel);
        observer.observe(select, { childList: true, attributes: true });
        select.addEventListener('change', updateLabel);
        select._observer = observer;

        container.appendChild(trigger);
        container.appendChild(optionsList);
        select.parentNode.insertBefore(container, select);
        select.classList.add('hidden', 'custom-init');
    });

    document.addEventListener('click', (e) => {
        if (!e.target.closest('.dropdown-container')) {
            document.querySelectorAll('.dropdown-options').forEach(el => el.classList.remove('show'));
            document.querySelectorAll('.dropdown-trigger').forEach(el => el.classList.remove('open'));
        }
    });
}