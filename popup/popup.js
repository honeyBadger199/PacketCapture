// HAR Capture - Popup Logic

const recordBtn = document.getElementById("recordBtn");
const exportBtn = document.getElementById("exportBtn");
const clearBtn = document.getElementById("clearBtn");
const statusIndicator = document.getElementById("statusIndicator");
const statusText = document.getElementById("statusText");
const requestCount = document.getElementById("requestCount");
const totalSize = document.getElementById("totalSize");
const elapsed = document.getElementById("elapsed");
const tabUrl = document.getElementById("tabUrl");
const statsGrid = document.getElementById("statsGrid");
const errorMessage = document.getElementById("errorMessage");

let pollInterval = null;
let currentTabId = null;

// ─── Init ───────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
    // Get current tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
        currentTabId = tab.id;
        tabUrl.textContent = truncateUrl(tab.url);
        tabUrl.title = tab.url;
    }

    // Get current state
    updateStatus();
});

// ─── Button Handlers ────────────────────────────────────────────────────────

recordBtn.addEventListener("click", async () => {
    const status = await getStatus();

    if (status.isRecording) {
        // Stop recording
        recordBtn.disabled = true;
        const result = await sendMessage({ action: "stopRecording" });
        if (result.success) {
            stopPolling();
            updateUI(false, result.entryCount, result.totalSize);
            showSuccess("Recording stopped — " + result.entryCount + " requests captured");
        } else {
            showError(result.error || "Failed to stop recording");
        }
        recordBtn.disabled = false;
    } else {
        // Start recording
        if (!currentTabId) {
            showError("No active tab found");
            return;
        }
        hideError();
        recordBtn.disabled = true;
        const result = await sendMessage({ action: "startRecording", tabId: currentTabId });
        if (result.success) {
            updateUI(true, 0, 0);
            startPolling();
        } else {
            showError(result.error || "Failed to start recording. Make sure you're on a regular webpage.");
        }
        recordBtn.disabled = false;
    }
});

exportBtn.addEventListener("click", async () => {
    const result = await sendMessage({ action: "exportHar" });
    if (result && result.har) {
        downloadHar(result.har);
    } else {
        showError("No HAR data to export");
    }
});

clearBtn.addEventListener("click", async () => {
    await sendMessage({ action: "clearEntries" });
    requestCount.textContent = "0";
    totalSize.textContent = "0 B";
    elapsed.textContent = "00:00";
    exportBtn.disabled = true;
    clearBtn.disabled = true;
    hideError();
});

// ─── Status Polling ─────────────────────────────────────────────────────────

function startPolling() {
    stopPolling();
    pollInterval = setInterval(updateStatus, 800);
}

function stopPolling() {
    if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
    }
}

async function updateStatus() {
    const status = await getStatus();
    updateUI(status.isRecording, status.entryCount, status.totalSize, status.startTime);

    if (status.isRecording) {
        if (!pollInterval) startPolling();
    }
}

function updateUI(isRecording, count, size, startTime) {
    // Status indicator
    if (isRecording) {
        statusIndicator.classList.add("recording");
        statusText.textContent = "Recording";
        recordBtn.classList.add("recording");
        recordBtn.querySelector("span").textContent = "Stop Recording";
        recordBtn.querySelector("svg").innerHTML = '<rect x="6" y="6" width="12" height="12" rx="2"/>';
        statsGrid.classList.add("recording");
    } else {
        statusIndicator.classList.remove("recording");
        statusText.textContent = count > 0 ? "Captured" : "Idle";
        recordBtn.classList.remove("recording");
        recordBtn.querySelector("span").textContent = "Start Recording";
        recordBtn.querySelector("svg").innerHTML = '<circle cx="12" cy="12" r="8"/>';
        statsGrid.classList.remove("recording");
    }

    // Stats
    requestCount.textContent = count || 0;
    totalSize.textContent = formatBytes(size || 0);

    // Timer
    if (isRecording && startTime) {
        const elapsedMs = Date.now() - startTime;
        elapsed.textContent = formatTime(elapsedMs);
    } else if (!isRecording && count === 0) {
        elapsed.textContent = "00:00";
    }

    // Buttons
    exportBtn.disabled = !count || count === 0;
    clearBtn.disabled = !count || count === 0;
}

// ─── HAR Download ───────────────────────────────────────────────────────────

function downloadHar(har) {
    const blob = new Blob([JSON.stringify(har, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);

    chrome.downloads.download({
        url: url,
        filename: `HARCaptures/capture_${timestamp}.har`,
        saveAs: false,
        conflictAction: "uniquify"
    }, (downloadId) => {
        if (chrome.runtime.lastError) {
            showError("Download failed: " + chrome.runtime.lastError.message);
        } else {
            showSuccess("Saved to Downloads/HARCaptures/");
        }
        URL.revokeObjectURL(url);
    });
}

// ─── Helpers ────────────────────────────────────────────────────────────────

async function sendMessage(msg) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage(msg, (response) => {
            resolve(response || {});
        });
    });
}

async function getStatus() {
    return sendMessage({ action: "getStatus" });
}

function formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    const value = (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0);
    return value + " " + units[i];
}

function formatTime(ms) {
    const totalSec = Math.floor(ms / 1000);
    const min = Math.floor(totalSec / 60).toString().padStart(2, "0");
    const sec = (totalSec % 60).toString().padStart(2, "0");
    return min + ":" + sec;
}

function truncateUrl(url) {
    if (!url) return "No tab selected";
    try {
        const u = new URL(url);
        const path = u.pathname.length > 30 ? u.pathname.slice(0, 30) + "…" : u.pathname;
        return u.hostname + path;
    } catch {
        return url.slice(0, 50);
    }
}

function showError(msg) {
    errorMessage.textContent = msg;
    errorMessage.classList.add("visible");
    errorMessage.style.background = "rgba(239, 68, 68, 0.1)";
    errorMessage.style.borderColor = "rgba(239, 68, 68, 0.2)";
    errorMessage.style.color = "#fca5a5";
}

function showSuccess(msg) {
    errorMessage.textContent = msg;
    errorMessage.classList.add("visible");
    errorMessage.style.background = "rgba(34, 197, 94, 0.1)";
    errorMessage.style.borderColor = "rgba(34, 197, 94, 0.2)";
    errorMessage.style.color = "#86efac";
    setTimeout(() => hideError(), 4000);
}

function hideError() {
    errorMessage.classList.remove("visible");
}
