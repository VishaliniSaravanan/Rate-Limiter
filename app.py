import os
import time
import json
import queue
import threading
from flask import Flask, request, jsonify, Response
from dotenv import load_dotenv
from rate_limiter import TokenBucket
from ml_classifier import MLClassifier

load_dotenv()

app = Flask(__name__)

RATE  = float(os.getenv("RATE", 5))
BURST = int(os.getenv("BURST", 10))

limiter    = TokenBucket(rate=RATE, burst=BURST)
classifier = MLClassifier()

_sse_clients = []
_sse_lock = threading.Lock()

def broadcast(data: dict):
    msg = f"data: {json.dumps(data)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(msg)
            except Exception:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)

@app.before_request
def rate_limit_middleware():
    if request.path.startswith("/dashboard") or request.path.startswith("/api/"):
        return

    user_id    = request.remote_addr
    path       = request.path
    user_agent = request.headers.get("User-Agent", "")

    profile   = classifier.get_profile(user_id)
    dyn_rate  = profile["dynamic_rate"]  if profile else None
    dyn_burst = profile["dynamic_burst"] if profile else None

    allowed = limiter.allow_request(user_id, override_rate=dyn_rate, override_burst=dyn_burst)
    classification, score = classifier.record_request(
        user_id, path=path, user_agent=user_agent, blocked=not allowed
    )

    broadcast({
        "type": "request",
        "user_id": user_id,
        "path": path,
        "allowed": allowed,
        "classification": classification,
        "score": round(score, 1),
        "ts": time.time(),
    })

    if not allowed:
        return jsonify({"error": "Too many requests. Please slow down."}), 429, {"Retry-After": "1"}

# ── Sample API Routes ──────────────────

@app.route("/hello")
def hello():
    return jsonify({"message": "Hello, world!"})

@app.route("/items")
def items():
    return jsonify({"items": ["apple", "banana", "cherry"]})

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return jsonify({"query": q, "results": []})

# ── Dashboard ──

@app.route("/dashboard")
def dashboard():
    # Read dashboard.html from the same folder as app.py
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()
    return Response(html, mimetype="text/html")

# ── API Endpoints ─────────

@app.route("/api/stats")
def api_stats():
    return jsonify(classifier.get_global_stats())

@app.route("/api/users")
def api_users():
    return jsonify(classifier.get_all_users())

@app.route("/api/user/<user_id>")
def api_user(user_id):
    profile = classifier.get_profile(user_id)
    if not profile:
        return jsonify({"error": "Not found"}), 404
    return jsonify(profile)

@app.route("/api/stream")
def api_stream():
    q = queue.Queue(maxsize=100)
    with _sse_lock:
        _sse_clients.append(q)

    def generate():
        yield f"data: {json.dumps({'type':'init','stats': classifier.get_global_stats()})}\n\n"
        try:
            while True:
                try:
                    msg = q.get(timeout=15)
                    yield msg
                except queue.Empty:
                    yield ": ping\n\n"
        except GeneratorExit:
            with _sse_lock:
                if q in _sse_clients:
                    _sse_clients.remove(q)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ── Background Stats Broadcaster ─────────

def _stats_broadcaster():
    while True:
        time.sleep(2)
        try:
            broadcast({"type": "stats", **classifier.get_global_stats()})
        except Exception:
            pass

threading.Thread(target=_stats_broadcaster, daemon=True).start()

if __name__ == "__main__":
    print("\n RateGuard is running!")
    print(" Dashboard → http://localhost:5000/dashboard")
    print(" API       → http://localhost:5000/hello\n")
    app.run(host="0.0.0.0", port=5000, debug=False)