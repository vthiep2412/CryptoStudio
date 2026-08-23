export function initTheme() {
    const savedTheme = localStorage.getItem('theme');
    const systemPrefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
    const isLight = savedTheme === 'light' || (!savedTheme && systemPrefersLight);

    if (isLight) {
        document.documentElement.classList.add('light');
        const meta = document.querySelector('meta[name="color-scheme"]');
        if (meta) meta.content = 'light';
    } else {
        document.documentElement.classList.remove('light');
        const meta = document.querySelector('meta[name="color-scheme"]');
        if (meta) meta.content = 'dark';
    }

    updateThemeIcons();
}

export function toggleTheme(event) {
    const x = event.clientX;
    const y = event.clientY;
    const endRadius = Math.hypot(
        Math.max(x, innerWidth - x),
        Math.max(y, innerHeight - y)
    );

    const isTransition = !!document.startViewTransition;

    const performToggle = () => {
        document.documentElement.classList.toggle('light');
        const isLight = document.documentElement.classList.contains('light');
        localStorage.setItem('theme', isLight ? 'light' : 'dark');
        updateThemeIcons();

        const meta = document.querySelector('meta[name="color-scheme"]');
        if (meta) meta.content = isLight ? 'light' : 'dark';
    };

    if (!isTransition) {
        performToggle();
        return;
    }

    const transition = document.startViewTransition(performToggle);

    transition.ready.then(() => {
        const clipPath = [
            `circle(0px at ${x}px ${y}px)`,
            `circle(${endRadius}px at ${x}px ${y}px)`,
        ];
        document.documentElement.animate(
            { clipPath: clipPath },
            {
                duration: 700,
                easing: 'cubic-bezier(0.4, 0, 0.2, 1)',
                pseudoElement: '::view-transition-new(root)',
            }
        );
    }).catch(err => {
        console.warn('View transition was skipped or failed:', err);
    });
}

function updateThemeIcons() {
    const isLight = document.documentElement.classList.contains('light');
    const sunIcon = document.getElementById('sunIcon');
    const moonIcon = document.getElementById('moonIcon');
    if (sunIcon) sunIcon.classList.toggle('hidden', !isLight);
    if (moonIcon) moonIcon.classList.toggle('hidden', isLight);
}