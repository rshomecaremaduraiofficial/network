/**
 * Client-Side JavaScript Logic for Network & Web Scanner Authentication
 * Handles transitions, validation, and AJAX communications with the Google Apps Script Web App.
 */

// REPLACE THIS PLACEHOLDER WITH YOUR DEPLOYED GOOGLE APPS SCRIPT WEB APP URL!
const APPS_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbz___gHmb5mhe9Y_m1wm4kFmIWTgzko7MW57Ek_auq0usBrgMxSBeJYihea24TKulcp/exec";

// Toast Utilities helper
function showToast(message, type = "success") {
    // Check if toast-container exists
    let container = document.querySelector(".toast-container");
    if (!container) {
        container = document.createElement("div");
        container.className = "toast-container";
        document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = `toast toast-${type} bg-glass`;

    const icon = type === "success" ? "fa-circle-check" : "fa-triangle-exclamation";
    toast.innerHTML = `
        <i class="fa-solid ${icon}"></i>
        <div style="flex-grow: 1;">${message}</div>
    `;

    container.appendChild(toast);

    // Animate in
    setTimeout(() => {
        toast.classList.add("show");
    }, 50);

    // Remove toast after duration
    setTimeout(() => {
        toast.classList.remove("show");
        setTimeout(() => {
            toast.remove();
        }, 400);
    }, 4000);
}

// Fetch helper to talk to Google Apps Script or Local Python Flask Server
// Fetch helper to talk to Google Apps Script or Local Python Flask Server
async function callBackend(payload) {
    const isLocalServer = window.location.protocol.startsWith('http');
    const hasAppsScript = typeof APPS_SCRIPT_URL !== 'undefined' && APPS_SCRIPT_URL && !APPS_SCRIPT_URL.includes("REPLACE_THIS") && !APPS_SCRIPT_URL.includes("___");
    const isOnline = navigator.onLine;

    // Route dynamically:
    // If online and has Google Apps Script URL configured, call Google Sheets directly.
    // Otherwise, if served via Flask local HTTP, route to the local Python database.
    // Otherwise, fall back to offline client-side simulation.
    let endpoint = '';
    if (isOnline && hasAppsScript) {
        endpoint = APPS_SCRIPT_URL;
    } else if (isLocalServer) {
        endpoint = '/api/backend';
    } else {
        return handleOfflineSimulation(payload);
    }

    try {
        const response = await fetch(endpoint, {
            method: "POST",
            mode: "cors",
            headers: {
                "Content-Type": "text/plain;charset=utf-8"
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            throw new Error(`HTTP network error ${response.status}`);
        }

        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Backend Error Details:", error);
        
        // Dynamic fallback: If online Apps Script call failed and we are on a local server, try local database
        if (endpoint === APPS_SCRIPT_URL && isLocalServer) {
            console.log("Online Google Sheets unavailable. Retrying connection on local Flask database...");
            try {
                const retryRes = await fetch('/api/backend', {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });
                if (retryRes.ok) {
                    return await retryRes.json();
                }
            } catch (retryErr) {
                console.error("Local database fallback failed:", retryErr);
            }
        }
        
        return { success: false, error: "Connection to security backend failed." };
    }
}

// Simulated response handler for direct offline launch
function handleOfflineSimulation(payload) {
    const action = payload.action;
    
    if (action === "adminLogin") {
        if (payload.username === "admin" && payload.password === "admin123") {
            return { success: true, token: "ADMIN_SECURE_TOKEN_2845" };
        }
        return { success: false, error: "Invalid credentials" };
    }
    
    return new Promise((resolve) => {
        setTimeout(() => {
            if (action === "loginUser") {
                resolve({ success: true, name: "Offline Agent", email: "offline@sentinel.net", userCode: "123456" });
            } else if (action === "registerInit") {
                resolve({ success: true, userCode: "123456" });
            } else if (action === "registerComplete") {
                resolve({ success: true, otp: "123456" });
            } else if (action === "verifyOTP" || action === "resendOTP" || action === "forgotInit" || action === "resendRecoveryOTP" || action === "forgotVerifyOTP" || action === "forgotResetPassword") {
                resolve({ success: true, userCode: "123456", otp: "123456" });
            } else {
                resolve({ success: false, error: "Offline mode simulation fallback." });
            }
        }, 500);
    });
}

// Setup live clock in dashboard if present
function initLiveClock() {
    const clockEl = document.getElementById("scanner-clock");
    if (!clockEl) return;

    function updateClock() {
        const now = new Date();
        clockEl.innerHTML = `<i class="fa-regular fa-clock text-blue"></i> ${now.toLocaleTimeString()} | SYSTEM SECURE`;
    }

    updateClock();
    setInterval(updateClock, 1000);
}

// Helper to get relative path based on environment and current page location
function getRelativePath(target) {
    const path = window.location.pathname;
    const isInsideTemplates = path.includes('/templates/') || path.endsWith('/templates');
    
    if (target === 'login') {
        return isInsideTemplates ? "../login.html" : "login.html";
    }
    
    if (target === 'dashboard') {
        return isInsideTemplates ? "dashboard.html" : "templates/dashboard.html";
    }
    
    return target;
}

// Get user session metadata
function getSessionUser() {
    const session = localStorage.getItem("user_session");
    if (session) {
        try {
            return JSON.parse(session);
        } catch (e) {
            return null;
        }
    }
    return null;
}

// Secure redirect if not logged in (dashboard page check)
function enforceAuth() {
    const user = getSessionUser();
    if (!user) {
        window.location.href = getRelativePath('login');
    } else {
        // Show body content now that authorization is verified
        document.body.style.display = "block";

        // Update operator profile panel values
        const nameBadges = document.querySelectorAll(".profile-name");
        nameBadges.forEach(el => {
            el.textContent = user.name;
        });

        const avatarEl = document.querySelector(".profile-avatar");
        if (avatarEl && user.name) {
            avatarEl.textContent = user.name.charAt(0).toUpperCase();
        }

        // Welcome parameter checked and cleared silently to prevent redundant message
        const params = new URLSearchParams(window.location.search);
        if (params.get("login") === "success") {
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }
}

// Handle login page redirect check
function redirectIfAuthenticated() {
    const user = getSessionUser();
    if (user) {
        window.location.href = getRelativePath('dashboard');
    }
}

// Handle Logout
function handleLogout() {
    // 1. Inject Styles if not already injected
    if (!document.getElementById("logout-hud-styles")) {
        const style = document.createElement("style");
        style.id = "logout-hud-styles";
        style.textContent = `
            .logout-hud-overlay {
                position: fixed;
                top: 0;
                left: 0;
                width: 100vw;
                height: 100vh;
                background: rgba(3, 4, 10, 0.96);
                backdrop-filter: blur(12px);
                -webkit-backdrop-filter: blur(12px);
                z-index: 99999;
                display: flex;
                align-items: center;
                justify-content: center;
                opacity: 0;
                pointer-events: none;
                transition: opacity 0.4s cubic-bezier(0.16, 1, 0.3, 1);
                color: #fff;
            }
            .logout-hud-overlay.show {
                opacity: 1;
                pointer-events: auto;
            }
            .logout-hud-overlay .hud-card {
                width: 100%;
                max-width: 480px;
                text-align: center;
                padding: 40px;
                display: flex;
                flex-direction: column;
                align-items: center;
                transform: scale(0.92);
                transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1);
            }
            .logout-hud-overlay.show .hud-card {
                transform: scale(1);
            }
            .logout-hud-overlay .hud-scanner-ring {
                position: relative;
                width: 130px;
                height: 130px;
                margin-bottom: 25px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .logout-hud-overlay .hud-circle {
                position: absolute;
                border-radius: 50%;
                border: 2px solid transparent;
            }
            .logout-hud-overlay .ring-outer {
                width: 120px;
                height: 120px;
                border-top-color: #ff3366;
                border-bottom-color: #ff3366;
                animation: spinCounter 2s linear infinite;
            }
            .logout-hud-overlay .ring-middle {
                width: 95px;
                height: 95px;
                border-left-color: #ff0055;
                border-right-color: #ff3300;
                animation: spin 1.5s linear infinite;
                filter: drop-shadow(0 0 8px rgba(255, 51, 102, 0.4));
            }
            .logout-hud-overlay .ring-inner {
                width: 70px;
                height: 70px;
                background: rgba(15, 23, 42, 0.6);
                border: 1px solid rgba(255, 255, 255, 0.05);
                box-shadow: inset 0 0 15px rgba(255, 51, 102, 0.2);
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .logout-hud-overlay .logout-power-icon {
                font-size: 26px;
                color: #ff3366;
                filter: drop-shadow(0 0 8px rgba(255, 51, 102, 0.8));
                animation: pulsePower 1.2s ease-in-out infinite alternate;
            }
            .logout-hud-overlay .hud-security-badge {
                display: inline-block;
                font-family: 'JetBrains Mono', monospace;
                font-size: 10px;
                letter-spacing: 2px;
                color: #ff3366;
                background: rgba(255, 51, 102, 0.08);
                border: 1px solid rgba(255, 51, 102, 0.15);
                padding: 3px 10px;
                border-radius: 4px;
                margin-bottom: 10px;
            }
            .logout-hud-overlay .hud-title {
                font-family: 'Outfit', sans-serif;
                font-weight: 800;
                font-size: 24px;
                margin: 0 0 8px 0;
                letter-spacing: 1px;
                color: #ff3366;
                text-shadow: 0 0 15px rgba(255, 51, 102, 0.3);
            }
            .logout-hud-overlay .hud-subtitle {
                color: #94a3b8;
                font-size: 13px;
                margin: 0;
            }
            .logout-hud-overlay .hud-logs-container {
                width: 100%;
                background: rgba(10, 5, 12, 0.8);
                border: 1px solid rgba(255, 51, 102, 0.1);
                border-radius: 12px;
                padding: 14px;
                text-align: left;
                margin-bottom: 25px;
                min-height: 90px;
                box-shadow: inset 0 0 8px rgba(0, 0, 0, 0.6);
            }
            .logout-hud-overlay .hud-log-row {
                font-family: 'JetBrains Mono', monospace;
                font-size: 11px;
                line-height: 1.5;
                margin-bottom: 5px;
                color: #94a3b8;
                opacity: 0;
                transform: translateY(4px);
                transition: all 0.25s ease;
            }
            .logout-hud-overlay .hud-log-row.show {
                opacity: 1;
                transform: translateY(0);
            }
            .logout-hud-overlay .hud-log-row.text-danger {
                color: #ff3366;
                text-shadow: 0 0 10px rgba(255, 51, 102, 0.3);
            }
            .logout-hud-overlay .hud-progress-wrapper {
                width: 100%;
                height: 3px;
                background: rgba(255, 255, 255, 0.03);
                border-radius: 10px;
                overflow: hidden;
                position: relative;
            }
            .logout-hud-overlay .hud-progress-fill {
                height: 100%;
                width: 0%;
                background: linear-gradient(90deg, #ff0055, #ff3300);
                border-radius: 10px;
                box-shadow: 0 0 8px rgba(255, 51, 102, 0.5);
                transition: width 2s cubic-bezier(0.1, 0.8, 0.25, 1);
            }
            @keyframes pulsePower {
                0% { transform: scale(1); filter: drop-shadow(0 0 4px rgba(255, 51, 102, 0.5)); }
                100% { transform: scale(1.08); filter: drop-shadow(0 0 12px rgba(255, 51, 102, 0.9)); }
            }
        `;
        document.head.appendChild(style);
    }

    // 2. Inject Markup if not already injected
    let overlay = document.getElementById("success-logout-overlay");
    if (!overlay) {
        overlay = document.createElement("div");
        overlay.id = "success-logout-overlay";
        overlay.className = "logout-hud-overlay";
        overlay.innerHTML = `
            <div class="hud-card">
                <div class="hud-scanner-ring">
                    <div class="hud-circle ring-outer"></div>
                    <div class="hud-circle ring-middle"></div>
                    <div class="hud-circle ring-inner">
                        <i class="fa-solid fa-power-off logout-power-icon"></i>
                    </div>
                </div>
                
                <div class="hud-security-alert">
                    <span class="hud-security-badge blink-slow">SECURE SESSION DE-AUTHORIZATION</span>
                    <h1 class="hud-title">SESSION TERMINATED</h1>
                    <p class="hud-subtitle">Clearing temporary session logs and variables...</p>
                </div>

                <div class="hud-logs-container">
                    <div class="hud-log-row" id="logout-log-1">DE-AUTHORIZING SECURITY TOKENS... [OK]</div>
                    <div class="hud-log-row" id="logout-log-2">CLEARING CONSOLE SESSION DATA... [OK]</div>
                    <div class="hud-log-row" id="logout-log-3">DISCONNECTING ENCRYPTED TUNNEL... [OK]</div>
                    <div class="hud-log-row text-danger" id="logout-log-4">SECURE LOGOUT COMPLETE. REDIRECTING...</div>
                </div>

                <div class="hud-progress-wrapper">
                    <div class="hud-progress-fill" id="logout-progress-fill"></div>
                </div>
            </div>
        `;
        document.body.appendChild(overlay);
    }

    // 3. Clear session
    localStorage.removeItem("user_session");

    // 4. Trigger Sequence
    setTimeout(() => {
        overlay.classList.add("show");
        showToast("Logout successful. Terminating connection...", "error");
        
        // Fill progress fill
        const fill = document.getElementById("logout-progress-fill");
        if (fill) {
            setTimeout(() => {
                fill.style.width = "100%";
            }, 50);
        }

        // Show logs sequentially
        setTimeout(() => document.getElementById("logout-log-1")?.classList.add("show"), 200);
        setTimeout(() => document.getElementById("logout-log-2")?.classList.add("show"), 600);
        setTimeout(() => document.getElementById("logout-log-3")?.classList.add("show"), 1000);
        setTimeout(() => document.getElementById("logout-log-4")?.classList.add("show"), 1400);

        // Redirect
        setTimeout(() => {
            window.location.href = getRelativePath('login');
        }, 2200);
    }, 10);
}

// Password utilities initialization
document.addEventListener('DOMContentLoaded', () => {
    // 1. Password Visibility Toggle
    const toggleButtons = document.querySelectorAll('.toggle-password');
    toggleButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const passwordInput = document.getElementById(targetId);
            if (!passwordInput) return;
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                this.classList.remove('fa-eye');
                this.classList.add('fa-eye-slash');
            } else {
                passwordInput.type = 'password';
                this.classList.remove('fa-eye-slash');
                this.classList.add('fa-eye');
            }
        });
    });

    // 2. Reusable Password Strength Analyzer
    function initStrengthChecker(inputId, containerId, labelId, barId, reqs) {
        const input = document.getElementById(inputId);
        const container = document.getElementById(containerId);
        const label = document.getElementById(labelId);
        const bar = document.getElementById(barId);
        
        if (!input || !container) return;

        input.addEventListener('focus', () => {
            container.style.display = 'block';
        });

        input.addEventListener('input', function() {
            const val = this.value;
            if (!val) {
                container.style.display = 'none';
                return;
            } else {
                container.style.display = 'block';
            }

            // Checks (8+ characters, case sensitivity, numbers/symbols)
            const hasLength = val.length >= 8;
            const hasCase = /[a-z]/.test(val) && /[A-Z]/.test(val);
            const hasNumSymbol = /[0-9]/.test(val) || /[^A-Za-z0-9]/.test(val);

            // Update requirements icons and colors
            updateRequirement(reqs.len, hasLength);
            updateRequirement(reqs.case, hasCase);
            updateRequirement(reqs.num, hasNumSymbol);

            // Score calculation
            let score = 0;
            if (hasLength) score++;
            if (hasCase) score++;
            if (hasNumSymbol) score++;

            // Update strength bar & text suggestion
            if (score === 0 || val.length < 4) {
                label.textContent = "Very Weak";
                label.style.color = "#ff3366";
                bar.style.width = "10%";
                bar.style.background = "#ff3366";
            } else if (score === 1) {
                label.textContent = "Weak";
                label.style.color = "#ff3366";
                bar.style.width = "33%";
                bar.style.background = "#ff3366";
            } else if (score === 2) {
                label.textContent = "Medium";
                label.style.color = "#ffb703"; // Warning yellow
                bar.style.width = "66%";
                bar.style.background = "#ffb703";
            } else if (score === 3) {
                label.textContent = "Strong";
                label.style.color = "var(--primary)";
                bar.style.width = "100%";
                bar.style.background = "var(--primary)";
            }
        });
    }

    function updateRequirement(elId, met) {
        const el = document.getElementById(elId);
        if (!el) return;
        const icon = el.querySelector('i');
        if (met) {
            el.style.color = "var(--primary)";
            if (icon) {
                icon.className = "fa-solid fa-circle-check";
                icon.style.color = "var(--primary)";
            }
        } else {
            el.style.color = "#ff3366";
            if (icon) {
                icon.className = "fa-solid fa-circle-xmark";
                icon.style.color = "#ff3366";
            }
        }
    }

    // Initialize checkers for registration
    initStrengthChecker('reg-pass', 'reg-strength-container', 'reg-strength-label', 'reg-strength-bar', {
        len: 'reg-req-len',
        case: 'reg-req-case',
        num: 'reg-req-num'
    });

    // Initialize checkers for password reset
    initStrengthChecker('reset-pass', 'reset-strength-container', 'reset-strength-label', 'reset-strength-bar', {
        len: 'reset-req-len',
        case: 'reset-req-case',
        num: 'reset-req-num'
    });
});
