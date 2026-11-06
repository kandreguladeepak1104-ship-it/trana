/* ============================================================
   TRANA shared helpers
   Load this script before each page's own <script> block.
   ============================================================ */

const PAPERS_KEY = "tranaPapers";
const SETTINGS_KEY = "tranaSettings";

localStorage.getItem("tranaPapers")

const DEFAULT_SETTINGS = {
    name: "Administrator",
    email: "",
    confirmRelease: true
};


/* ---------- Papers storage ---------- */

function getPapers() {
    try {
        return JSON.parse(localStorage.getItem(PAPERS_KEY)) || [];
    } catch (e) {
        return [];
    }
}

function savePapers(papers) {
    localStorage.setItem(PAPERS_KEY, JSON.stringify(papers));
}


/* ---------- Settings storage ---------- */

function getSettings() {
    try {
        return {
            ...DEFAULT_SETTINGS,
            ...(JSON.parse(localStorage.getItem(SETTINGS_KEY)) || {})
        };
    } catch (e) {
        return { ...DEFAULT_SETTINGS };
    }
}

function saveSettings(settings) {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
    applyProfile();
}


/* ---------- Rendering helpers ---------- */

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, ch => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    }[ch]));
}

function formatExamDate(date, time) {
    if (!date) return "—";
    const d = new Date(`${date}T${time || "00:00"}`);
    if (isNaN(d)) return escapeHtml(date);
    return d.toLocaleString(undefined, {
        day: "numeric",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit"
    });
}

function statusBadge(paper) {
    if (paper.delivered) return '<span class="status delivered">✓ Delivered</span>';
    if (paper.scheduled) return '<span class="status scheduled">◷ Scheduled</span>';
    if (paper.encrypted) return '<span class="status encrypted">🔒 Encrypted</span>';
    return '<span class="status">● Not encrypted</span>';
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


/* ---------- Profile (name shown in topbar and welcome card) ---------- */

function applyProfile() {
    const name = getSettings().name || "Administrator";

    document.querySelectorAll("[data-admin-name]").forEach(el => {
        el.textContent = name;
    });

    document.querySelectorAll("[data-admin-initial]").forEach(el => {
        el.textContent = name.charAt(0).toUpperCase();
    });
}

document.addEventListener("DOMContentLoaded", applyProfile);


/* ---------- Logout ---------- */

function logout(event) {
    if (event) event.preventDefault();

    if (confirm("Are you sure you want to logout?")) {
        window.location.href = "login.html";
    }
}
