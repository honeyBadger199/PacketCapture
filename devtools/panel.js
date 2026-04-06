// HAR Capture - DevTools Panel Logic

const recordBtn = document.getElementById("recordBtn");
const clearBtn = document.getElementById("clearBtn");
const exportBtn = document.getElementById("exportBtn");
const statusInfo = document.getElementById("statusInfo");
const filterInput = document.getElementById("filterInput");
const requestCountBadge = document.getElementById("requestCountBadge");
const requestTableBody = document.getElementById("requestTableBody");

let pollInterval = null;
let currentEntries = [];
let filterText = "";

// ─── Init ───────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
    updatePanel();
    startPolling();
});

// ─── Button Handlers ────────────────────────────────────────────────────────

recordBtn.addEventListener("click", async () => {
    const status = await sendMessage({ action: "getStatus" });

    if (status.isRecording) {
        await sendMessage({ action: "stopRecording" });
        recordBtn.classList.remove("recording");
        statusInfo.classList.remove("recording");
        statusInfo.textContent = "Stopped";
    } else {
        // Get inspected tab
        const tabId = chrome.devtools.inspectedWindow.tabId;
        const result = await sendMessage({ action: "startRecording", tabId });
        if (result.success) {
            recordBtn.classList.add("recording");
            statusInfo.classList.add("recording");
            statusInfo.textContent = "● Recording";
        } else {
            statusInfo.textContent = "Error: " + (result.error || "Failed");
        }
    }
});

clearBtn.addEventListener("click", async () => {
    await sendMessage({ action: "clearEntries" });
    currentEntries = [];
    renderTable();
});

exportBtn.addEventListener("click", async () => {
    const result = await sendMessage({ action: "exportHar" });
    if (result && result.har) {
        const blob = new Blob([JSON.stringify(result.har, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);

        chrome.downloads.download({
            url: url,
            filename: `HARCaptures/capture_${timestamp}.har`,
            saveAs: false,
            conflictAction: "uniquify"
        }, () => {
            URL.revokeObjectURL(url);
        });
    }
});

// ─── Filter ─────────────────────────────────────────────────────────────────

filterInput.addEventListener("input", (e) => {
    filterText = e.target.value.toLowerCase();
    renderTable();
});

// ─── Polling ────────────────────────────────────────────────────────────────

function startPolling() {
    pollInterval = setInterval(updatePanel, 1000);
}

async function updatePanel() {
    const status = await sendMessage({ action: "getStatus" });

    if (status.isRecording) {
        recordBtn.classList.add("recording");
        statusInfo.classList.add("recording");
        statusInfo.textContent = "● Recording";
    } else {
        recordBtn.classList.remove("recording");
        statusInfo.classList.remove("recording");
        if (currentEntries.length > 0) {
            statusInfo.textContent = "Captured";
        } else {
            statusInfo.textContent = "Idle";
        }
    }

    // Fetch entries
    const entriesResult = await sendMessage({ action: "getEntries" });
    if (entriesResult && entriesResult.entries) {
        currentEntries = entriesResult.entries;
        renderTable();
    }
}

// ─── Table Rendering ────────────────────────────────────────────────────────

function renderTable() {
    const filtered = filterText
        ? currentEntries.filter(e => e.url.toLowerCase().includes(filterText))
        : currentEntries;

    requestCountBadge.textContent = filtered.length + " request" + (filtered.length !== 1 ? "s" : "");

    if (filtered.length === 0) {
        requestTableBody.innerHTML = `
      <tr class="empty-state">
        <td colspan="6">
          <div class="empty-content">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="1.5">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="8" x2="12" y2="12"/>
              <circle cx="12" cy="15" r="0.5" fill="#555"/>
            </svg>
            <p>${filterText ? "No requests match your filter" : "Click the record button to start capturing"}</p>
          </div>
        </td>
      </tr>`;
        return;
    }

    requestTableBody.innerHTML = filtered.map(entry => {
        const statusClass = getStatusClass(entry.status);
        const methodClass = "method-" + entry.method;
        const isError = entry.status >= 400 || entry.status === 0;
        const urlPath = getUrlPath(entry.url);

        return `<tr class="${isError ? "error" : ""}">
      <td><span class="method-badge ${methodClass}">${entry.method}</span></td>
      <td class="${statusClass}">${entry.status || "—"}</td>
      <td title="${escapeHtml(entry.url)}">${escapeHtml(urlPath)}</td>
      <td>${entry.resourceType || entry.mimeType.split("/").pop()}</td>
      <td style="text-align:right">${formatBytes(entry.size)}</td>
      <td style="text-align:right">${entry.time}ms</td>
    </tr>`;
    }).join("");
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function getStatusClass(status) {
    if (!status || status === 0) return "status-0";
    if (status < 300) return "status-2xx";
    if (status < 400) return "status-3xx";
    if (status < 500) return "status-4xx";
    return "status-5xx";
}

function getUrlPath(url) {
    try {
        const u = new URL(url);
        return u.pathname + u.search;
    } catch {
        return url;
    }
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return "0 B";
    const units = ["B", "KB", "MB"];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + " " + units[i];
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}

async function sendMessage(msg) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage(msg, (response) => {
            resolve(response || {});
        });
    });
}
