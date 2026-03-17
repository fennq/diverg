# Verify Live PoC + Extension

## 1. Start the API

```bash
cd /path/to/Sectester
pip install -r requirements.txt   # if not already
python api_server.py
```

Leave it running. Default: http://127.0.0.1:5000

## 2. Test PoC endpoint (optional)

```bash
curl -s -X POST http://127.0.0.1:5000/api/poc/simulate \
  -H "Content-Type: application/json" \
  -d '{"finding":{"url":"https://httpbin.org/get","title":"Possible IDOR","category":"Access Control"},"param_to_change":"user_id","new_value":"2"}'
```

You should get JSON with `success`, `conclusion`, `body_preview`, `status_code`.

## 3. Load the extension

1. Open Chrome → `chrome://extensions/`
2. Turn on **Developer mode**
3. Click **Load unpacked**
4. Select the **`extension`** folder inside Sectester

## 4. Run a scan and click Simulate

1. Click the Diverg icon in the toolbar.
2. Enter a URL. **Good test target:** **https://solanafunded.com** (you’ve scanned it before; see reports/sectester_solanafunded.com_*.json). Findings like “Dangerous HTTP methods enabled without auth” on /admin/ or /phpMyAdmin/ will show a Simulate button. Or click **Use current tab**.
3. Click **Scan**. Wait for "Done. N findings."
4. Click **View last results** (opens the results page).
5. On the results page, find a finding that has a **Simulate** button (IDOR-like or unauthenticated findings with a URL).
6. Click **Simulate**. A modal should show the PoC result (conclusion, status code, body preview).

If the API is not running, the popup scan will fail with "Request failed" and Simulate will show "Request failed: Failed to fetch".
