/* ============================================================
   TRANA shared helpers (complete file)
   - api(): sends requests to the backend and shows real errors
   - login check, logout, and display helpers
   Load this file before any page script.
   ============================================================ */

const API_BASE = "http://localhost:3000/api";

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

    console.log("API", method, path, token ? "(token sent)" : "(NO TOKEN)");

    let res;
    try {
        res = await fetch(API_BASE + path, { method, headers, body });
    } catch (err) {
        throw new Error("Cannot reach the TRANA server. Is python app.py running?");
    }

    const data = await res.json().catch(() => ({}));
    console.log("API result", res.status, data);

    if (!res.ok) {
        const message = data.error || ("Request failed (" + res.status + ")");

        /* Token rejected: show the server's reason, then go to login */
        if (res.status === 401 && path !== "/auth/login") {
            localStorage.removeItem("tranaToken");
            alert(message + "\n\nPlease log in again.");
            window.location.href = "login.html";
        }

        throw new Error(message);
    }

    return data;
}

/* ---------- Login and logout ---------- */

function requireLogin() {
    if (!localStorage.getItem("tranaToken")) {
        window.location.href = "login.html";
    }
}

function logout(event) {
    if (event) event.preventDefault();

    if (confirm("Are you sure you want to logout?")) {
        localStorage.removeItem("tranaToken");
        localStorage.removeItem("tranaName");
        window.location.href = "login.html";
    }
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

    document.querySelectorAll("[data-admin-name]").forEach(el => {
        el.textContent = name;
    });

    document.querySelectorAll("[data-admin-initial]").forEach(el => {
        el.textContent = name.charAt(0).toUpperCase();
    });
}

document.addEventListener("DOMContentLoaded", applyProfile);