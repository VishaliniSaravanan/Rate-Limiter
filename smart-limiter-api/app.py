import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from rate_limiter import TokenBucket

load_dotenv()

app = Flask(__name__)

RATE = float(os.getenv("RATE", 5))
BURST = int(os.getenv("BURST", 10))

limiter = TokenBucket(rate=RATE, burst=BURST)

@app.before_request
def rate_limit_middleware():
    user_id = request.remote_addr

    if not limiter.allow_request(user_id):
        response = jsonify({"error": "Too many requests. Please slow down."})
        response.status_code = 429
        response.headers["Retry-After"] = "1"
        return response

@app.route("/hello")
def hello():
    return jsonify({"message": "Hello, world!"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
