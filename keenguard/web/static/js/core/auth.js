// ==========================================
// Authentication & 401 Interceptor
// ==========================================
let isAuthModalOpen = false;
let currentAuthStatus = null;

const _originalFetch = window.fetch;
window.fetch = async function(...args) {
    const response = await _originalFetch.apply(this, args);
    if (response.status === 401) {
        const url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
        if (url.includes('/api/') && !url.includes('/api/auth/login') && !url.includes('/api/auth/status')) {
            showLoginModal();
        }
    }
    return response;
};

async function checkAuthStatus() {
    try {
        const res = await _originalFetch('/api/auth/status');
        if (res.ok) {
            const data = await res.json();
            currentAuthStatus = data;
            updateWebAccessBadges(data.web_host, true, data.is_localhost);
            if (data.auth_required && !data.authenticated) {
                showLoginModal();
            } else if (!isAuthModalOpen) {
                hideLoginModal();
            }
        }
    } catch (err) {
        console.debug('Failed to check auth status:', err);
    }
}

function updateWebAccessBadges(webHost, hasPassword, isLocal) {
    const badgeText = document.getElementById('auth-status-text');
    const badgeIcon = document.getElementById('auth-status-icon');
    const modeBadge = document.getElementById('web-access-mode-badge');
    const isExposed = webHost && webHost !== '127.0.0.1' && webHost !== 'localhost';

    if (badgeText) {
        if (isExposed) {
            badgeText.textContent = '0.0.0.0 (LAN открыт)';
        } else {
            badgeText.textContent = '127.0.0.1 (Локально)';
        }
    }
    if (badgeIcon) {
        if (isExposed) {
            badgeIcon.setAttribute('data-lucide', 'shield-alert');
            badgeIcon.className = 'w-3.5 h-3.5 text-amber-400';
        } else {
            badgeIcon.setAttribute('data-lucide', 'shield-check');
            badgeIcon.className = 'w-3.5 h-3.5 text-emerald-400';
        }
    }
    if (modeBadge) {
        if (isExposed) {
            modeBadge.textContent = '0.0.0.0 (Доступен в LAN)';
            modeBadge.className = 'px-2.5 py-1 rounded-lg text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20';
        } else {
            modeBadge.textContent = '127.0.0.1 (Закрыт для LAN)';
            modeBadge.className = 'px-2.5 py-1 rounded-lg text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';
        }
    }
    if (window.lucide && typeof lucide.createIcons === 'function') {
        lucide.createIcons();
    }
}

function showLoginModal(errorMessage = '') {
    const modal = document.getElementById('login-modal');
    if (!modal) return;
    modal.classList.remove('hidden');
    isAuthModalOpen = true;
    const errBox = document.getElementById('login-error-box');
    const errMsg = document.getElementById('login-error-message');
    if (errBox && errMsg) {
        if (errorMessage) {
            errMsg.textContent = errorMessage;
            errBox.classList.remove('hidden');
        } else {
            errBox.classList.add('hidden');
        }
    }
    const input = document.getElementById('login-password-input');
    if (input) {
        input.value = '';
        setTimeout(() => input.focus(), 100);
    }
    if (window.lucide) lucide.createIcons();
}

function hideLoginModal() {
    const modal = document.getElementById('login-modal');
    if (modal) modal.classList.add('hidden');
    isAuthModalOpen = false;
}

function toggleLoginPasswordVisibility() {
    const input = document.getElementById('login-password-input');
    const icon = document.getElementById('login-pwd-eye-icon');
    if (!input) return;
    if (input.type === 'password') {
        input.type = 'text';
        if (icon) icon.setAttribute('data-lucide', 'eye-off');
    } else {
        input.type = 'password';
        if (icon) icon.setAttribute('data-lucide', 'eye');
    }
    if (window.lucide) lucide.createIcons();
}

async function submitLogin(e) {
    if (e && e.preventDefault) e.preventDefault();
    const input = document.getElementById('login-password-input');
    const btn = document.getElementById('btn-login-submit');
    const btnText = document.getElementById('login-submit-text');
    const errBox = document.getElementById('login-error-box');
    const errMsg = document.getElementById('login-error-message');

    const password = input ? input.value : '';
    if (!password) return;

    if (btn) btn.disabled = true;
    if (btnText) btnText.textContent = 'Проверка...';
    if (errBox) errBox.classList.add('hidden');

    try {
        const res = await _originalFetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });
        const data = await res.json();
        if (res.ok && data.authenticated) {
            hideLoginModal();
            showToast('Вход выполнен успешно', 'success');
            checkAuthStatus();
            connectWebSocket();
            refreshAllData();
        } else {
            const msg = data.detail || 'Неверный пароль';
            if (errBox && errMsg) {
                errMsg.textContent = msg;
                errBox.classList.remove('hidden');
            }
            if (input) {
                input.value = '';
                input.focus();
            }
        }
    } catch (err) {
        if (errBox && errMsg) {
            errMsg.textContent = 'Ошибка сети при авторизации: ' + err.message;
            errBox.classList.remove('hidden');
        }
    } finally {
        if (btn) btn.disabled = false;
        if (btnText) btnText.textContent = 'Войти в панель';
        if (window.lucide) lucide.createIcons();
    }
}

async function logout() {
    try {
        await _originalFetch('/api/auth/logout', { method: 'POST' });
        showToast('Панель заблокирована', 'info');
    } catch (err) {
        console.error('Logout error:', err);
    } finally {
        showLoginModal();
    }
}

function handleAuthBadgeClick() {
    navigateToSettingsSubTab('web-access');
}

function onWebHostRadioChange(host) {
    updateWebAccessBadges(host);
    const feedback = document.getElementById('web-pw-feedback');
    if (feedback) {
        if (host === '0.0.0.0') {
            feedback.textContent = 'Внимание: при привязке к 0.0.0.0 интерфейс станет доступен в локальной сети. Убедитесь, что задан надежный пароль!';
            feedback.className = 'text-xs text-amber-400 block';
        } else {
            feedback.textContent = 'Интерфейс будет привязан к 127.0.0.1 (только этот компьютер).';
            feedback.className = 'text-xs text-emerald-400 block';
        }
    }
}

async function loadWebAccessSettings() {
    try {
        const res = await fetch('/api/settings/network_access');
        if (!res.ok) return;
        const data = await res.json();
        const rLocal = document.getElementById('cfg-web-host-local');
        const rAny = document.getElementById('cfg-web-host-any');
        if (data.web_host === '0.0.0.0') {
            if (rAny) rAny.checked = true;
        } else {
            if (rLocal) rLocal.checked = true;
        }
        const exemptCb = document.getElementById('cfg-web-auth-exempt-localhost');
        if (exemptCb && data.web_auth_exempt_localhost !== undefined) {
            exemptCb.checked = Boolean(data.web_auth_exempt_localhost);
        }
        const pwStatus = document.getElementById('web-pw-status-text');
        if (pwStatus) {
            if (data.has_web_password) {
                pwStatus.textContent = 'Установлен';
                pwStatus.className = 'font-semibold text-emerald-400';
            } else {
                pwStatus.textContent = 'Не установлен (без пароля)';
                pwStatus.className = 'font-semibold text-amber-400';
            }
        }
        updateWebAccessBadges(data.web_host, data.has_web_password);
    } catch (e) {
        console.debug('Failed to load network access settings:', e);
    }
}

async function submitChangeWebPassword() {
    const oldInput = document.getElementById('cfg-web-old-password');
    const newInput = document.getElementById('cfg-web-new-password');
    const confirmInput = document.getElementById('cfg-web-confirm-password');
    const feedback = document.getElementById('web-pw-feedback');
    const btn = document.getElementById('btn-save-web-password');

    const oldPassword = oldInput ? oldInput.value : '';
    const newPassword = newInput ? newInput.value : '';
    const confirmPassword = confirmInput ? confirmInput.value : '';

    if (!newPassword || newPassword.length < 6) {
        if (feedback) {
            feedback.textContent = 'Новый пароль должен содержать не менее 6 символов!';
            feedback.className = 'text-xs text-rose-400 block';
        }
        return;
    }
    if (newPassword !== confirmPassword) {
        if (feedback) {
            feedback.textContent = 'Новый пароль и подтверждение не совпадают!';
            feedback.className = 'text-xs text-rose-400 block';
        }
        return;
    }

    if (btn) btn.disabled = true;
    try {
        const res = await fetch('/api/auth/change_password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                old_password: oldPassword,
                new_password: newPassword,
            })
        });
        const data = await res.json();
        if (res.ok) {
            showToast('Пароль администратора успешно изменен', 'success');
            if (feedback) {
                feedback.textContent = 'Пароль успешно обновлен и сохранен в .env';
                feedback.className = 'text-xs text-emerald-400 block';
            }
            if (oldInput) oldInput.value = '';
            if (newInput) newInput.value = '';
            if (confirmInput) confirmInput.value = '';
            loadWebAccessSettings();
        } else {
            if (feedback) {
                feedback.textContent = data.detail || 'Ошибка изменения пароля';
                feedback.className = 'text-xs text-rose-400 block';
            }
        }
    } catch (err) {
        if (feedback) {
            feedback.textContent = 'Ошибка сети: ' + err.message;
            feedback.className = 'text-xs text-rose-400 block';
        }
    } finally {
        if (btn) btn.disabled = false;
    }
}

function generateRandomWebPassword() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!#$*';
    let pwd = '';
    const arr = new Uint8Array(12);
    window.crypto.getRandomValues(arr);
    for (let i = 0; i < 12; i++) {
        pwd += chars[arr[i] % chars.length];
    }
    const newInput = document.getElementById('cfg-web-new-password');
    const confirmInput = document.getElementById('cfg-web-confirm-password');
    if (newInput) {
        newInput.type = 'text';
        newInput.value = pwd;
    }
    if (confirmInput) {
        confirmInput.type = 'text';
        confirmInput.value = pwd;
    }
    const feedback = document.getElementById('web-pw-feedback');
    if (feedback) {
        feedback.textContent = `Сгенерирован пароль: ${pwd} (скопируйте его и нажмите "Сменить пароль")`;
        feedback.className = 'text-xs text-cyan-400 block font-mono';
    }
}

window.checkAuthStatus = checkAuthStatus;
window.showLoginModal = showLoginModal;
window.hideLoginModal = hideLoginModal;
window.submitLogin = submitLogin;
window.logout = logout;
window.toggleLoginPasswordVisibility = toggleLoginPasswordVisibility;
window.handleAuthBadgeClick = handleAuthBadgeClick;
window.onWebHostRadioChange = onWebHostRadioChange;
window.loadWebAccessSettings = loadWebAccessSettings;
window.submitChangeWebPassword = submitChangeWebPassword;
window.generateRandomWebPassword = generateRandomWebPassword;

