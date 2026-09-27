from flask import Flask, request, jsonify
from waf.detector import detect_attack
from waf.rate_limiter import is_rate_limited
from waf.logger import log_event

app = Flask(__name__)

from flask import render_template
from collections import Counter
import csv as _csv
import os

def read_logs():
    if not os.path.exists("logs/events.csv"):
        return []
    with open("logs/events.csv", newline="") as f:
        return list(_csv.DictReader(f))

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def catch_all(path):
    ip = request.remote_addr
    method = request.method
    full_path = request.full_path
    body = request.get_data(as_text=True)
    headers = str(request.headers)
    query = request.query_string.decode()
    payload = f"{full_path} {query} {body}"

    # 1. Rate limit check
    if is_rate_limited(ip):
        log_event(ip, method, full_path, payload, "Rate Limit", "block", "Too many requests", 429)
        return jsonify({"status": "blocked", "reason": "rate limit"}), 429

    # 2. Attack detection
    rule = detect_attack(payload)
    if rule:
        log_event(ip, method, full_path, payload, rule["category"], rule["action"],
                  rule["id"], 403 if rule["action"] == "block" else 200)
        if rule["action"] == "block":
            return jsonify({"status": "blocked", "category": rule["category"]}), 403
        else:
            return jsonify({"status": "flagged", "category": rule["category"]}), 200

    # 3. Normal request
    log_event(ip, method, full_path, payload, "Normal", "allow", "No match", 200)
    return jsonify({"status": "allowed", "path": path}), 200


@app.route('/dashboard')
def dashboard():
    rows = read_logs()
    total = len(rows)
    blocked = sum(1 for r in rows if r["action"] == "block")
    allowed = sum(1 for r in rows if r["action"] == "allow")
    flagged = sum(1 for r in rows if r["action"] == "flag")

    categories = Counter(r["category"] for r in rows)
    top_ips = Counter(r["ip"] for r in rows).most_common(5)
    recent = list(reversed(rows[-20:]))

    return render_template(
        "dashboard.html",
        total=total, blocked=blocked, allowed=allowed, flagged=flagged,
        categories=categories, top_ips=top_ips, recent=recent
    )
if __name__ == '__main__':
    app.run(debug=True)