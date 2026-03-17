# API: Live PoC / Simulate

The extension can offer a **“Simulate”** (or “Run PoC”) button per finding. When the user clicks it, the extension calls the backend to run a minimal proof-of-concept and shows the result.

## Endpoint

**POST /api/poc/simulate**

- **Content-Type:** application/json
- **Body:** either a **finding** object (backend infers PoC type) or explicit **type** + **url** + optional params.

---

## Option 1: Send the finding (recommended)

The extension sends the finding from the scan report. The backend infers whether to run an IDOR or unauthenticated PoC from `title` and `category`.

```json
{
  "finding": {
    "url": "https://example.com/api/orders?user_id=123",
    "title": "Possible IDOR on /api/orders",
    "category": "Access Control",
    "evidence": "user_id in query string"
  },
  "param_to_change": "user_id",
  "new_value": "456",
  "cookies": {}
}
```

- **param_to_change** (optional): for IDOR, which parameter to change. If omitted, we try to infer from evidence or common names (`user_id`, `userId`, `id`, `order_id`, etc.).
- **new_value** (optional): value to use in the modified request. Default `"1"`.
- **cookies** (optional): if the endpoint requires auth, the extension can pass cookies (e.g. from the current tab). Backend will send them with the PoC request.

**Response:**

```json
{
  "success": true,
  "status_code": 200,
  "body_preview": "{\"orders\":[...]}",
  "conclusion": "IDOR likely: request with user_id=456 returned 200 with a different response. Verify manually that the data belongs to another user.",
  "error": null,
  "poc_type": "idor"
}
```

- **success:** true if we could run the request (no network error).
- **status_code:** HTTP status of the modified (or unauth) request.
- **body_preview:** first 500 chars of response body (safe for UI).
- **conclusion:** short human-readable result (e.g. “IDOR likely” or “No IDOR: 403”).
- **error:** set if success is false (e.g. missing url, requests failed).
- **poc_type:** `"idor"` or `"unauthenticated"`.

---

## Option 2: Explicit type + url

For more control, send the PoC type and URL directly:

**IDOR:**

```json
{
  "type": "idor",
  "url": "https://example.com/api/orders?user_id=123",
  "method": "GET",
  "param_to_change": "user_id",
  "new_value": "456",
  "params": {},
  "headers": {},
  "cookies": {}
}
```

**Unauthenticated:**

```json
{
  "type": "unauthenticated",
  "url": "https://example.com/api/admin/users",
  "method": "GET",
  "headers": {},
  "cookies": {}
}
```

The backend strips auth-related headers for the unauthenticated PoC.

---

## When we infer “idor” vs “unauthenticated”

- **idor:** finding title or category contains “IDOR”, “insecure direct object”, “object reference”, or category is “Access Control” and title has “id”/“user”/“account”.
- **unauthenticated:** title contains “unauthenticated”, “no auth”, “without auth”.

If we can’t infer a type, the response will have `success: false` and `error` explaining. The extension can show “Simulate” only for findings that have a `url` and fall into IDOR or unauthenticated categories, or the extension can send `finding.poc_type` explicitly (`"idor"` or `"unauthenticated"`).

---

## Extension integration

1. In the findings list, for each finding that has a `url` and is IDOR- or unauthenticated-like (or has `poc_type`), show a **“Simulate”** button.
2. On click, **POST** the finding (and optional `param_to_change`, `new_value`, `cookies`) to **/api/poc/simulate**.
3. Show the response in a small modal or inline:
   - **conclusion** (main message)
   - **status_code**
   - **body_preview** (expandable or in a code block)
   - If **error**, show it instead.

Optional: pass the current tab’s cookies for the same origin so the PoC runs in the same auth context (backend will send them; ensure same-origin or CORS allows the API to be called from the extension).
