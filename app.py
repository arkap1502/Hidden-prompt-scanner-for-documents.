#!/usr/bin/env python3
"""Local web UI for Hidden-Prompt Scanner. Run: python app.py -> http://127.0.0.1:5000"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from detectors import SUPPORTED, scan_file

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "File too large (max 32 MB)"}), 413


@app.errorhandler(400)
def bad_request(_e):
    # Flask raises this for malformed JSON bodies; keep API JSON, not HTML.
    return jsonify({"error": "Bad request (malformed upload or JSON)"}), 400


@app.get("/")
def index():
    return render_template("index.html", supported=sorted(SUPPORTED))


@app.post("/api/scan")
def api_scan():
    files = request.files.getlist("files")
    if not files or all(not f.filename for f in files):
        return jsonify({"error": "No files uploaded"}), 400
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        for f in files:
            if not f.filename:
                continue
            suffix = Path(f.filename).suffix.lower()
            if suffix not in SUPPORTED:
                results.append({
                    "file": f.filename, "file_type": suffix or "unknown",
                    "risk": "LOW", "score": 0, "finding_count": 1,
                    "findings": [{"type": "skipped", "location": f.filename,
                                  "detail": f"Unsupported type '{suffix}'. Supported: {sorted(SUPPORTED)}",
                                  "excerpt": "", "severity": "low", "weight": 0}],
                })
                continue
            dest = Path(tmp) / Path(f.filename).name  # .name strips any directory traversal
            f.save(dest)
            try:
                report = scan_file(dest)
            except Exception as e:  # never 500 on a bad file
                report = {"file": f.filename, "file_type": suffix, "risk": "LOW",
                          "score": 1, "finding_count": 1,
                          "findings": [{"type": "error", "location": f.filename,
                                        "detail": f"Scan failed: {e}", "excerpt": "",
                                        "severity": "low", "weight": 1}]}
            report["file"] = f.filename  # show original name, not temp path
            results.append(report)
    summary = {r: sum(1 for x in results if x["risk"] == r) for r in ("HIGH", "MEDIUM", "LOW", "CLEAN")}
    return jsonify({"files_scanned": len(results), "summary": summary, "results": results})


@app.post("/api/text")
def api_text():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "") if isinstance(data, dict) else ""
    if not text.strip():
        return jsonify({"error": "Empty text"}), 400
    try:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "pasted.txt"
            p.write_text(text, encoding="utf-8")
            report = scan_file(p)
    except Exception as e:
        return jsonify({"error": f"Scan failed: {e}"}), 500
    report["file"] = "pasted-text.txt"
    return jsonify(report)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    # 0.0.0.0 so hosting platforms (Render, Railway) can reach the app.
    # Locally, still open http://127.0.0.1:5000 in your browser.
    app.run(host="0.0.0.0", port=port, debug=False)
