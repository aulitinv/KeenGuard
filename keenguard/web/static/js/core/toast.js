// ==========================================
// Toast Notification Subsystem
// ==========================================
function showToast(msg, isError = false) {
    let container = document.getElementById('kg-toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'kg-toast-container';
        container.className = 'fixed bottom-5 right-5 z-[9999] flex flex-col space-y-2 pointer-events-none';
        document.body.appendChild(container);
    }
    const toast = document.createElement('div');
    toast.className = `px-4 py-2.5 rounded-xl text-xs font-medium shadow-xl transition-all duration-300 transform translate-y-2 opacity-0 pointer-events-auto flex items-center space-x-2 border ${
        isError ? 'bg-rose-950/90 text-rose-200 border-rose-500/50' : 'bg-slate-900/95 text-slate-100 border-indigo-500/40'
    }`;
    toast.innerHTML = `<span>${escapeHtml(msg)}</span>`;
    container.appendChild(toast);
    requestAnimationFrame(() => {
        toast.classList.remove('translate-y-2', 'opacity-0');
    });
    setTimeout(() => {
        toast.classList.add('opacity-0', 'translate-y-2');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}
window.showToast = showToast;

function clearAllToasts() {
    const container = document.getElementById('kg-toast-container');
    if (container) container.innerHTML = '';
}
window.clearAllToasts = clearAllToasts;
