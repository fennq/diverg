# API: Streaming and natural-language goal

Maximum-feature usage of the Diverg scan API: **streaming progress** and **goal-based scans**.

## POST /api/scan (with goal)

- **Body:** `{"url": "https://example.com", "goal": "payment bypass and headers"}`
- **goal** is optional. When present, only skills that match the goal run (faster, focused).
- **Goal examples:** `"payment bypass"`, `"rug risk"`, `"headers"`, `"SQL injection"`, `"full audit"`, `"admin panel"`, `"client-side"`, `"auth"`, `"API"`, `"OWASP"`. Unknown goals fall back to full scan.
- Response shape unchanged: `target_url`, `findings`, `scanned_at`, `summary`, `skills_run`.

## POST /api/scan/stream (NDJSON stream)

- **Body:** same as `/api/scan`: `{"url": "https://...", "goal": "optional"}`
- **Response:** `Content-Type: application/x-ndjson` — one JSON object per line.

### Events

| event        | payload | meaning |
|-------------|---------|--------|
| `skill_start` | `skill` | A skill is about to run. |
| `skill_done`  | `skill`, `findings_count`, optional `error` | Skill finished; show count (or error). |
| `done`        | `report` | Full report (same shape as `/api/scan`). Use this for results. |
| `error`       | `error` | Scan failed. |

### Example (JavaScript) — consume stream in extension

```javascript
const res = await fetch('http://127.0.0.1:5000/api/scan/stream', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ url: tabUrl, goal: goalInput?.value?.trim() || undefined })
});
const reader = res.body.getReader();
const decoder = new TextDecoder();
let buffer = '';
while (true) {
  const { value, done } = await reader.read();
  if (done) break;
  buffer += decoder.decode(value, { stream: true });
  const lines = buffer.split('\n');
  buffer = lines.pop() || '';
  for (const line of lines) {
    if (!line.trim()) continue;
    const event = JSON.parse(line);
    if (event.event === 'skill_start') setStatus(`Running ${event.skill}…`);
    if (event.event === 'skill_done') setStatus(`${event.skill}: ${event.findings_count} findings`);
    if (event.event === 'done') {
      const report = event.report;
      // store report, open results page, etc.
    }
    if (event.event === 'error') setStatus('Error: ' + event.error);
  }
}
```

Use **stream** when you want live progress (e.g. “Running headers_ssl…”, “headers_ssl: 5 findings”). Use **non-stream** when you only need the final JSON and don’t need to show progress.

## RAG citations in findings

When the platform runs a full (or goal-based) scan, each finding may include a **citations** array: chunks from the content library (exploit catalog, prevention docs) that support remediation. Use `finding.citations` in the UI to show “Sources” or “Learn more”. Optional: set `OPENAI_API_KEY` so the RAG index uses embeddings for better citation relevance.
