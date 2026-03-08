# Nmap Scanner Backend

A simple Flask backend that receives scan requests, runs Nmap safely, and returns results as JSON.

---

## Project Structure

```
backend/
├── app.py           # Flask app and API routes
├── scanner.py       # Runs Nmap and parses results
├── validators.py    # Input validation
├── requirements.txt # Python dependencies
└── README.md        # This file
```

---

## Prerequisites

### 1. Install Nmap

On macOS using Homebrew:

```bash
brew install nmap
```

Verify it works:

```bash
nmap --version
```

### 2. Install Python dependencies

It's recommended to use a virtual environment:

```bash
# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Running the Server

```bash
python app.py
```

The server starts on `http://localhost:5000`.

---

## API Endpoints

### `GET /health`

Returns the health status of the server.

**Example:**
```bash
curl http://localhost:5000/health
```

**Response:**
```json
{
  "status": "ok",
  "message": "Backend is running."
}
```

---

### `POST /api/scan`

Runs an Nmap scan against a target.

**Request body:**
```json
{
  "target": "scanme.nmap.org",
  "scan_type": "basic"
}
```

**Allowed `scan_type` values:**

| scan_type       | Nmap flags used       | Description                     |
|-----------------|-----------------------|---------------------------------|
| `basic`         | `-F`                  | Fast scan of common ports       |
| `top_ports`     | `--top-ports 100`     | Scans the top 100 ports         |
| `service_detect`| `-sV`                 | Detects service versions        |

**Example:**
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "scanme.nmap.org", "scan_type": "basic"}'
```

**Success response:**
```json
{
  "target": "scanme.nmap.org",
  "scan_type": "basic",
  "status": "completed",
  "open_ports": [22, 80]
}
```

**Error response (bad input):**
```json
{
  "error": "Invalid scan_type. Allowed values: basic, top_ports, service_detect."
}
```

---

## Security Notes

- Users **cannot** pass raw Nmap flags. Only predefined scan types are accepted.
- Input is validated with regex before being passed to the subprocess.
- `subprocess.run()` is called with a **list** (not a string), which fully prevents shell injection.
- The scan has a **60-second timeout** to prevent the server from hanging.
