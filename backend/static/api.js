/* ============================================================
   TRANA shared helpers
   - api(): sends requests to the backend and shows real errors
   - login check, logout, and display helpers
   Load this file before any page script.
   ============================================================ */

/* Same origin as the page, so it works on localhost and when deployed. */
const API_BASE = "/api";

async function api(path, options = {}) {
    const method = options.method || "GET";
    const headers = { ...(options.headers || {}) };
    let body = options.body;

    if (body && !(body instanceof FormData)) {
        headers["Content-Type"] = "application/json";
        body = JSON.stringify(body);
    }

    const token = localStorage.getItem("tranaToken");
    if (token) {
        headers["Authorization"] = "Bearer " + token;
    }

    let res;
    try {
        res = await fetch(API_BASE + path, { method, headers, body });
    } catch (err) {
        throw new Error("Cannot reach the TRANA server. Is the backend running?");
    }

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
        const message = data.error || ("Request failed (" + res.status + ")");

        /* Token rejected: clear it, tell the login page why, redirect once */
        if (res.status === 401 && path !== "/auth/login") {
            clearSession();
            sessionStorage.setItem("tranaNotice", message);
            window.location.replace("login.html");

            const expired = new Error(message);
            expired.sessionExpired = true;
            throw expired;
        }

        throw new Error(message);
    }

    return data;
}

/* ---------- Errors ---------- */

/* Alerts once. An expired session is already redirecting, so stay quiet. */
function reportError(err) {
    if (err && err.sessionExpired) return;
    alert((err && err.message) || "Something went wrong. Please try again.");
}

/* ---------- Session ---------- */

function clearSession() {
    localStorage.removeItem("tranaToken");
    localStorage.removeItem("tranaName");
    localStorage.removeItem("tranaRole");
}

function requireLogin() {
    if (!localStorage.getItem("tranaToken")) {
        window.location.replace("login.html");
    }
}

function logout(event) {
    if (event) event.preventDefault();

    if (confirm("Are you sure you want to logout?")) {
        clearSession();
        window.location.replace("login.html");
    }
}

function roleLabel() {
    const role = localStorage.getItem("tranaRole");

    if (role === "admin") return "Admin";
    if (role === "paper_setter") return "Paper Setter";

    return role ? role : "Member";
}

/* ---------- Display helpers ---------- */

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, ch => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[ch]));
}

function formatExamDate(iso) {
    if (!iso) return "—";
    return new Date(iso).toLocaleString(undefined, {
        day: "numeric", month: "short", year: "numeric",
        hour: "2-digit", minute: "2-digit"
    });
}

function statusBadge(paper) {
    if (paper.delivered) return '<span class="status delivered">✓ Delivered</span>';
    if (paper.scheduled) return '<span class="status scheduled">◷ Scheduled</span>';
    return '<span class="status encrypted">🔒 Encrypted</span>';
}

function paperNameCell(paper) {
    return `
        <div class="paper-name">
            <div class="paper-icon">📄</div>
            <div>
                <strong>${escapeHtml(paper.name)}</strong>
                <small>${escapeHtml(paper.fileName || "")}</small>
            </div>
        </div>`;
}

function applyProfile() {
    const name = localStorage.getItem("tranaName") || "Administrator";
    const role = roleLabel();

    document.querySelectorAll("[data-admin-name]").forEach(el => {
        el.textContent = name;
    });

    document.querySelectorAll("[data-admin-initial]").forEach(el => {
        el.textContent = name.charAt(0).toUpperCase();
    });

    document.querySelectorAll("[data-admin-role]").forEach(el => {
        el.textContent = role;
    });
}

document.addEventListener("DOMContentLoaded", applyProfile);
