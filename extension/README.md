# Extension tech (Sectester / Diverg repo)

**Extension tech** (API auto-detect, background worker, auto-scan logic) lives **here and in the diverg-extension repo**. This folder holds that tech so the main Diverg/Sectester repo has it.

**Extension front-end** (popup UI, options page, side panel UI, results page, icons, CSS) lives **only in the diverg-extension repo**. Load the extension in Chrome from that repo:

- **Load unpacked:** select the `diverg-extension` folder (not this folder).

Backend (api_server.py, orchestrator, skills) runs from this repo. The extension calls it; API is auto-detected at 127.0.0.1:5000 or localhost:5000.

## Tech files in this folder

- `background.js` — auto-scan on visit, calls `/api/scan`, opens side panel. (Same file in diverg-extension.)
- `api.js` — auto-detect API base. (Same file in diverg-extension.)

Keep these in sync with diverg-extension when you change extension tech.
