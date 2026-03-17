# Diverg Chrome Extension

Minimal extension to run Diverg scans and **Simulate** (Live PoC) on findings.

## Setup

1. **Start the API** (from the Sectester repo root):
   ```bash
   python api_server.py
   ```
   Default: http://127.0.0.1:5000

2. **Load the extension in Chrome**
   - Open `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `extension` folder (this directory)

3. **Options** (optional): Click the extension → "Options" to set a different API base URL.

## Usage

1. Click the Diverg icon in the toolbar.
2. Enter a URL or click "Use current tab", then **Scan**. (Uses quick scope for speed.)
3. When the scan finishes, click **View last results** (or open the results page from the extension).
4. On the results page, each finding that supports PoC (IDOR-like or unauthenticated) has a **Simulate** button.
5. Click **Simulate** on a finding. The extension calls `POST /api/poc/simulate` with that finding; the backend runs a minimal PoC and returns a conclusion. A modal shows the result (conclusion, status code, body preview).

## Where is the Simulate button?

On the **results page** (open it via "View last results" in the popup after a scan). Each finding row that has a URL and looks like an IDOR or unauthenticated finding will show a **Simulate** button. Click it to run the PoC and see the result in the modal.

## Test target (from your own scans)

Use **https://solanafunded.com** (you’ve scanned it before). The extension uses **API scope** so the scan runs `api_test` and returns findings like “Dangerous HTTP methods enabled without auth” on `/admin/`, `/phpMyAdmin/`. Every finding that has a URL now shows a **Simulate** button — click it to run the PoC.

If you still don’t see the button: (1) Run a fresh scan from the popup (don’t rely on old results). (2) After the scan finishes, click “View last results”. (3) You should see findings with URLs and a Simulate button on each.
