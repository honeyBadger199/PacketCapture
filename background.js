// HAR Capture - Background Service Worker
// Uses chrome.debugger API to capture full network traffic

const DEBUGGER_VERSION = "1.3";

// State management
let state = {
    isRecording: false,
    tabId: null,
    startTime: null,
    entries: [],
    requests: new Map(),   // requestId -> request data
    pageUrl: "",
    pageTitle: ""
};

// ─── Chrome Debugger Event Handler ──────────────────────────────────────────

chrome.debugger.onEvent.addListener((source, method, params) => {
    if (!state.isRecording || source.tabId !== state.tabId) return;

    switch (method) {
        case "Network.requestWillBeSent":
            handleRequestWillBeSent(params);
            break;
        case "Network.responseReceived":
            handleResponseReceived(params);
            break;
        case "Network.dataReceived":
            handleDataReceived(params);
            break;
        case "Network.loadingFinished":
            handleLoadingFinished(source, params);
            break;
        case "Network.loadingFailed":
            handleLoadingFailed(params);
            break;
    }
});

// ─── Network Event Handlers ─────────────────────────────────────────────────

function handleRequestWillBeSent(params) {
    const { requestId, request, timestamp, wallTime, initiator, type, redirectResponse } = params;

    // Handle redirect — finalize old entry
    if (redirectResponse && state.requests.has(requestId)) {
        finalizeRedirectEntry(requestId, redirectResponse, timestamp);
    }

    state.requests.set(requestId, {
        requestId,
        method: request.method,
        url: request.url,
        headers: request.headers,
        postData: request.postData || "",
        timestamp,
        wallTime: wallTime || Date.now() / 1000,
        initiator,
        resourceType: type || "Other",
        response: null,
        responseHeaders: {},
        responseBody: "",
        responseBodySize: 0,
        encodedDataLength: 0,
        finished: false,
        failed: false,
        errorText: "",
        timings: {
            send: 0,
            wait: 0,
            receive: 0
        }
    });
}

function handleResponseReceived(params) {
    const { requestId, response, timestamp, type } = params;
    const entry = state.requests.get(requestId);
    if (!entry) return;

    entry.response = response;
    entry.responseHeaders = response.headers || {};
    entry.statusCode = response.status;
    entry.statusText = response.statusText || "";
    entry.mimeType = response.mimeType || "";
    entry.protocol = response.protocol || "";
    entry.resourceType = type || entry.resourceType;
    entry.responseTimestamp = timestamp;

    // Timing info from response
    if (response.timing) {
        const t = response.timing;
        entry.detailedTiming = t;
    }
}

function handleDataReceived(params) {
    const { requestId, dataLength, encodedDataLength } = params;
    const entry = state.requests.get(requestId);
    if (!entry) return;

    entry.responseBodySize += dataLength;
    entry.encodedDataLength += encodedDataLength;
}

function handleLoadingFinished(source, params) {
    const { requestId, timestamp, encodedDataLength } = params;
    const entry = state.requests.get(requestId);
    if (!entry) return;

    entry.finished = true;
    entry.finishedTimestamp = timestamp;
    entry.encodedDataLength = encodedDataLength || entry.encodedDataLength;

    // Try to get response body
    chrome.debugger.sendCommand(
        { tabId: source.tabId },
        "Network.getResponseBody",
        { requestId },
        (result) => {
            if (chrome.runtime.lastError || !result) {
                entry.responseBody = "";
            } else {
                entry.responseBody = result.body || "";
                entry.responseBodyEncoding = result.base64Encoded ? "base64" : "";
            }
            // Build HAR entry and store
            const harEntry = buildHarEntry(entry);
            state.entries.push(harEntry);
        }
    );
}

function handleLoadingFailed(params) {
    const { requestId, errorText, timestamp } = params;
    const entry = state.requests.get(requestId);
    if (!entry) return;

    entry.failed = true;
    entry.finished = true;
    entry.errorText = errorText || "Failed";
    entry.finishedTimestamp = timestamp;

    const harEntry = buildHarEntry(entry);
    state.entries.push(harEntry);
}

function finalizeRedirectEntry(requestId, redirectResponse, timestamp) {
    const entry = state.requests.get(requestId);
    if (!entry) return;

    entry.response = redirectResponse;
    entry.responseHeaders = redirectResponse.headers || {};
    entry.statusCode = redirectResponse.status;
    entry.statusText = redirectResponse.statusText || "";
    entry.mimeType = redirectResponse.mimeType || "";
    entry.finished = true;
    entry.finishedTimestamp = timestamp;

    const harEntry = buildHarEntry(entry);
    state.entries.push(harEntry);
}

// ─── HAR Entry Builder ──────────────────────────────────────────────────────

function buildHarEntry(entry) {
    const startedDateTime = new Date(entry.wallTime * 1000).toISOString();

    // Calculate timings
    let timings = { blocked: -1, dns: -1, connect: -1, ssl: -1, send: 0, wait: 0, receive: 0 };
    let totalTime = 0;

    if (entry.detailedTiming) {
        const t = entry.detailedTiming;
        timings.blocked = Math.max(0, t.dnsStart > 0 ? t.dnsStart : (t.connectStart > 0 ? t.connectStart : t.sendStart));
        timings.dns = t.dnsEnd > 0 ? (t.dnsEnd - t.dnsStart) : -1;
        timings.connect = t.connectEnd > 0 ? (t.connectEnd - t.connectStart) : -1;
        timings.ssl = t.sslEnd > 0 ? (t.sslEnd - t.sslStart) : -1;
        timings.send = Math.max(0, t.sendEnd - t.sendStart);
        timings.wait = Math.max(0, (entry.responseTimestamp - entry.timestamp) * 1000 - timings.send);
        timings.receive = entry.finishedTimestamp ? Math.max(0, (entry.finishedTimestamp - entry.responseTimestamp) * 1000) : 0;
    } else if (entry.responseTimestamp && entry.finishedTimestamp) {
        timings.wait = Math.max(0, (entry.responseTimestamp - entry.timestamp) * 1000);
        timings.receive = Math.max(0, (entry.finishedTimestamp - entry.responseTimestamp) * 1000);
    }

    totalTime = Math.max(0,
        (timings.blocked > 0 ? timings.blocked : 0) +
        (timings.dns > 0 ? timings.dns : 0) +
        (timings.connect > 0 ? timings.connect : 0) +
        timings.send + timings.wait + timings.receive
    );

    // Parse headers
    const requestHeaders = objectToHeaders(entry.headers || {});
    const responseHeaders = objectToHeaders(entry.responseHeaders || {});

    // Build cookies (simple extraction from headers)
    const requestCookies = parseCookies(entry.headers?.Cookie || entry.headers?.cookie || "");
    const responseCookies = parseSetCookies(entry.responseHeaders?.["Set-Cookie"] || entry.responseHeaders?.["set-cookie"] || "");

    // Parse URL
    let parsedUrl = {};
    try {
        const url = new URL(entry.url);
        parsedUrl = {
            scheme: url.protocol.replace(":", ""),
            host: url.hostname,
            port: url.port || "",
            path: url.pathname,
            queryString: [...url.searchParams].map(([name, value]) => ({ name, value }))
        };
    } catch (e) {
        parsedUrl = { scheme: "", host: "", port: "", path: entry.url, queryString: [] };
    }

    // Build postData
    let postData = undefined;
    if (entry.postData) {
        const contentType = entry.headers?.["Content-Type"] || entry.headers?.["content-type"] || "application/octet-stream";
        postData = {
            mimeType: contentType,
            text: entry.postData,
            params: []
        };
        // Parse form data
        if (contentType.includes("application/x-www-form-urlencoded")) {
            try {
                postData.params = [...new URLSearchParams(entry.postData)].map(([name, value]) => ({ name, value }));
            } catch (e) { }
        }
    }

    // Response content
    const content = {
        size: entry.responseBodySize || 0,
        compression: Math.max(0, (entry.responseBodySize || 0) - (entry.encodedDataLength || 0)),
        mimeType: entry.mimeType || "application/octet-stream",
        text: entry.responseBody || "",
        encoding: entry.responseBodyEncoding || undefined
    };

    return {
        startedDateTime,
        time: totalTime,
        request: {
            method: entry.method,
            url: entry.url,
            httpVersion: entry.protocol || "HTTP/1.1",
            cookies: requestCookies,
            headers: requestHeaders,
            queryString: parsedUrl.queryString,
            postData,
            headersSize: JSON.stringify(requestHeaders).length,
            bodySize: entry.postData ? entry.postData.length : 0
        },
        response: {
            status: entry.statusCode || 0,
            statusText: entry.statusText || "",
            httpVersion: entry.protocol || "HTTP/1.1",
            cookies: responseCookies,
            headers: responseHeaders,
            content,
            redirectURL: entry.responseHeaders?.Location || entry.responseHeaders?.location || "",
            headersSize: JSON.stringify(responseHeaders).length,
            bodySize: entry.encodedDataLength || -1
        },
        cache: {},
        timings,
        serverIPAddress: entry.response?.remoteIPAddress || "",
        connection: entry.response?.connectionId?.toString() || "",
        _resourceType: entry.resourceType
    };
}

// ─── Helper Functions ───────────────────────────────────────────────────────

function objectToHeaders(headersObj) {
    return Object.entries(headersObj).map(([name, value]) => ({ name, value: String(value) }));
}

function parseCookies(cookieStr) {
    if (!cookieStr) return [];
    return cookieStr.split(";").map(c => {
        const [name, ...rest] = c.trim().split("=");
        return { name: name || "", value: rest.join("=") || "" };
    }).filter(c => c.name);
}

function parseSetCookies(setCookieStr) {
    if (!setCookieStr) return [];
    const cookies = Array.isArray(setCookieStr) ? setCookieStr : [setCookieStr];
    return cookies.map(c => {
        const parts = c.split(";")[0];
        const [name, ...rest] = parts.split("=");
        return { name: name?.trim() || "", value: rest.join("=") || "" };
    }).filter(c => c.name);
}

function buildHar() {
    return {
        log: {
            version: "1.2",
            creator: {
                name: "HAR Capture Extension",
                version: "1.0.0"
            },
            pages: [
                {
                    startedDateTime: state.startTime ? new Date(state.startTime).toISOString() : new Date().toISOString(),
                    id: "page_1",
                    title: state.pageTitle || state.pageUrl || "Captured Page",
                    pageTimings: {
                        onContentLoad: -1,
                        onLoad: -1
                    }
                }
            ],
            entries: state.entries.map(e => ({ ...e, pageref: "page_1" }))
        }
    };
}

// ─── Message Handler ────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.action) {
        case "startRecording":
            startRecording(message.tabId).then(result => sendResponse(result));
            return true; // async

        case "stopRecording":
            stopRecording().then(result => sendResponse(result));
            return true;

        case "getStatus":
            sendResponse({
                isRecording: state.isRecording,
                tabId: state.tabId,
                entryCount: state.entries.length,
                pendingCount: state.requests.size - state.entries.length,
                startTime: state.startTime,
                totalSize: state.entries.reduce((sum, e) => sum + (e.response?.content?.size || 0), 0)
            });
            break;

        case "exportHar":
            sendResponse({ har: buildHar() });
            break;

        case "getEntries":
            sendResponse({
                entries: state.entries.map(e => ({
                    method: e.request.method,
                    url: e.request.url,
                    status: e.response.status,
                    mimeType: e.response.content.mimeType,
                    size: e.response.content.size,
                    time: Math.round(e.time),
                    resourceType: e._resourceType
                }))
            });
            break;

        case "clearEntries":
            state.entries = [];
            state.requests.clear();
            sendResponse({ success: true });
            break;
    }
});

// ─── Recording Controls ─────────────────────────────────────────────────────

async function startRecording(tabId) {
    if (state.isRecording) {
        return { success: false, error: "Already recording" };
    }

    try {
        // Get tab info
        const tab = await chrome.tabs.get(tabId);
        state.tabId = tabId;
        state.pageUrl = tab.url;
        state.pageTitle = tab.title;
        state.entries = [];
        state.requests.clear();
        state.startTime = Date.now();

        // Attach debugger
        await chrome.debugger.attach({ tabId }, DEBUGGER_VERSION);

        // Enable network tracking
        await chrome.debugger.sendCommand({ tabId }, "Network.enable", {
            maxPostDataSize: 65536,
            maxTotalBufferSize: 100000000,
            maxResourceBufferSize: 10000000
        });

        // Optionally enable cache to get more accurate data
        await chrome.debugger.sendCommand({ tabId }, "Network.setCacheDisabled", { cacheDisabled: false });

        state.isRecording = true;

        // Update extension icon to show recording state
        chrome.action.setBadgeText({ text: "REC", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#FF4444", tabId });

        return { success: true };
    } catch (err) {
        state.isRecording = false;
        state.tabId = null;
        return { success: false, error: err.message };
    }
}

async function stopRecording() {
    if (!state.isRecording || !state.tabId) {
        return { success: false, error: "Not recording" };
    }

    try {
        await chrome.debugger.detach({ tabId: state.tabId });
    } catch (e) {
        // Tab might have been closed
    }

    // Wait a bit for any pending response bodies
    await new Promise(resolve => setTimeout(resolve, 500));

    state.isRecording = false;

    // Clear badge
    try {
        chrome.action.setBadgeText({ text: "", tabId: state.tabId });
    } catch (e) { }

    return {
        success: true,
        entryCount: state.entries.length,
        totalSize: state.entries.reduce((sum, e) => sum + (e.response?.content?.size || 0), 0)
    };
}

// Handle debugger detach (e.g. user closes the debugger bar)
chrome.debugger.onDetach.addListener((source, reason) => {
    if (source.tabId === state.tabId && state.isRecording) {
        state.isRecording = false;
        try {
            chrome.action.setBadgeText({ text: "", tabId: state.tabId });
        } catch (e) { }
    }
});

// Handle tab close
chrome.tabs.onRemoved.addListener((tabId) => {
    if (tabId === state.tabId && state.isRecording) {
        state.isRecording = false;
        state.tabId = null;
    }
});
