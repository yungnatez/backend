# Scan Me Solutions – Backend

This is the backend for the Scan Me Solutions web app. It exposes a simple REST API that runs Nmap scans and returns the results as JSON. The frontend just needs to hit the endpoints below — no setup required on your end.

---

## Live API

```
https://backend-production-fafd9.up.railway.app
```

---

## Endpoints

### GET /health
Check the server is up.

```
GET https://backend-production-fafd9.up.railway.app/health
```

Response:
```json
{
  "status": "ok",
  "message": "Backend is running."
}
```

---

### POST /api/scan
Run a scan against a target.

```
POST https://backend-production-fafd9.up.railway.app/api/scan
Content-Type: application/json
```

Request body:
```json
{
  "target": "scanme.nmap.org",
  "scan_type": "basic"
}
```

Scan types:

| scan_type | What it does |
|---|---|
| `basic` | Quick scan of the most common ports |
| `top_ports` | Scans the top 100 ports |
| `service_detect` | Detects what services are running on open ports |

Success response:
```json
{
  "target": "scanme.nmap.org",
  "scan_type": "basic",
  "status": "completed",
  "open_ports": [80, 443]
}
```

Error response (e.g. bad input):
```json
{
  "error": "Invalid scan_type. Allowed values: basic, top_ports, service_detect."
}
```

---

## Notes for the frontend

- All responses are JSON
- Scans take roughly 15–30 seconds — worth showing a loading state in the UI
- `open_ports` is always an array of integers (port numbers)
- If something goes wrong the response will have an `"error"` key with a description
- CORS is enabled so you can call the API directly from the browser with no issues

---

## Project structure

```
backend/
├── app.py           # Flask routes
├── scanner.py       # Runs Nmap and parses output
├── validators.py    # Input validation
├── requirements.txt # Python dependencies
├── Dockerfile       # Container setup (used by Railway)
└── railway.toml     # Railway config
```

---

## Running locally (optional)

You'll need Python 3 and Nmap installed (`brew install nmap` on Mac).

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Server runs on `http://localhost:5000`.
