# HAR Capture — Chromium Extension

A premium browser extension that captures all network traffic from any tab and exports it as standard HAR (HTTP Archive) files.

## Features

- **One-Click Recording** — Start/stop network capture from the popup
- **Full HAR 1.2 Support** — Headers, timing, cookies, request/response bodies
- **Live Stats** — Real-time request count, total size, and duration
- **DevTools Panel** — Detailed request table with filtering inside DevTools
- **Export** — Download captured traffic as `.har` files
- **Dark Theme** — Premium dark UI with smooth animations

## Installation

1. Open Chromium and navigate to `chrome://extensions`
2. Enable **Developer mode** (toggle in top-right)
3. Click **Load unpacked**
4. Select the `HARCapture` folder
5. The extension icon appears in the toolbar

## Usage

### Popup (Quick Capture)
1. Navigate to the website you want to capture
2. Click the **HAR Capture** extension icon in the toolbar
3. Click **Start Recording** — a "REC" badge appears on the icon
4. Browse the website normally — all network requests are captured
5. Click **Stop Recording** when done
6. Click **Export HAR** to download the `.har` file

### DevTools Panel (Detailed View)
1. Open DevTools (`F12` or `Ctrl+Shift+I`)
2. Go to the **HAR Capture** tab
3. Use the record/stop/clear/export buttons in the toolbar
4. Filter requests by URL using the search box
5. View method, status, URL, type, size, and timing for each request

## HAR File Usage

Open exported `.har` files in:
- [HAR Viewer](http://www.softwareishard.com/har/viewer/)  
- Chrome DevTools → Network tab → Import HAR
- [Google HAR Analyzer](https://toolbox.googleapps.com/apps/har_analyzer/)

## Permissions

| Permission | Why |
|---|---|
| `debugger` | Attach to tab for full network capture |
| `activeTab` | Access the current tab to start recording |
| `tabs` | Get tab URL and title for HAR metadata |
| `storage` | Persist extension state |

## Tech Stack

- **Manifest V3** — Modern Chromium extension format
- **Chrome DevTools Protocol** — Full network event capture via `Network` domain
- **Vanilla JS/CSS** — No frameworks, zero dependencies
