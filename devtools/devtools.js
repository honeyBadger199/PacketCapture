// Create HAR Capture panel in DevTools
chrome.devtools.panels.create(
    "HAR Capture",
    null,
    "devtools/panel.html",
    (panel) => {
        // Panel created
    }
);
