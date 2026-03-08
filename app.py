"""
app.py
Main Flask application. Defines the API routes and wires together
the validation and scanning logic.

Routes:
    GET  /health     -> Returns server health status.
    POST /api/scan   -> Accepts a scan request and returns results.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS

from validators import validate_target, validate_scan_type, get_nmap_flags
from scanner import run_scan

app = Flask(__name__)

# Enable CORS so the frontend (running on a different port) can call this API
CORS(app)


@app.route("/health", methods=["GET"])
def health():
    """Simple health check endpoint."""
    return jsonify({"status": "ok", "message": "Backend is running."}), 200


@app.route("/api/scan", methods=["POST"])
def scan():
    """
    Accepts a JSON body with 'target' and 'scan_type'.
    Validates both inputs, runs the nmap scan, and returns results.

    Expected request body:
        {
            "target": "scanme.nmap.org",
            "scan_type": "basic"
        }

    Success response:
        {
            "target": "scanme.nmap.org",
            "scan_type": "basic",
            "status": "completed",
            "open_ports": [22, 80]
        }
    """

    # --- 1. Parse the incoming JSON body ---
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body must be JSON."}), 400

    target = data.get("target", "").strip()
    scan_type = data.get("scan_type", "").strip()

    # --- 2. Validate inputs ---
    target_valid, target_error = validate_target(target)
    if not target_valid:
        return jsonify({"error": target_error}), 400

    scan_type_valid, scan_type_error = validate_scan_type(scan_type)
    if not scan_type_valid:
        return jsonify({"error": scan_type_error}), 400

    # --- 3. Get the safe nmap flags for this scan type ---
    nmap_flags = get_nmap_flags(scan_type)

    # --- 4. Run the scan ---
    result = run_scan(target, nmap_flags)

    # --- 5. Return the result ---
    if result["error"]:
        return jsonify({
            "target": target,
            "scan_type": scan_type,
            "status": "error",
            "error": result["error"],
        }), 500

    return jsonify({
        "target": target,
        "scan_type": scan_type,
        "status": "completed",
        "open_ports": result["open_ports"],
    }), 200


if __name__ == "__main__":
    # Run in debug mode for local development only
    # Do not use debug=True in production
    app.run(debug=True, host="0.0.0.0", port=5000)
