import time
import threading
import redis
import json
import os

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

try:
    r = redis.from_url(REDIS_URL, decode_responses=True)
    r.ping()
    REDIS_AVAILABLE = True
except Exception:
    REDIS_AVAILABLE = False
    print("[WARNING] Redis unavailable, falling back to in-memory store.")


class TokenBucket:
    def __init__(self, rate, burst):
        self.rate = rate
        self.burst = burst
        self.lock = threading.Lock()
        self._local = {}  # fallback

    def _get_bucket(self, user_id):
        if REDIS_AVAILABLE:
            key = f"bucket:{user_id}"
            data = r.get(key)
            if data:
                return json.loads(data)
        else:
            return self._local.get(user_id)
        return None

    def _set_bucket(self, user_id, tokens, last_refill):
        if REDIS_AVAILABLE:
            key = f"bucket:{user_id}"
            r.setex(key, 3600, json.dumps({"tokens": tokens, "last_refill": last_refill}))
        else:
            self._local[user_id] = (tokens, last_refill)

    def _refill(self, user_id, override_rate=None, override_burst=None):
        now = time.time()
        rate = override_rate or self.rate
        burst = override_burst or self.burst

        data = self._get_bucket(user_id)
        if data:
            if isinstance(data, dict):
                tokens, last_refill = data["tokens"], data["last_refill"]
            else:
                tokens, last_refill = data
        else:
            tokens, last_refill = burst, now

        elapsed = now - last_refill
        tokens = min(burst, tokens + elapsed * rate)
        return tokens, now

    def allow_request(self, user_id, override_rate=None, override_burst=None):
        with self.lock:
            tokens, now = self._refill(user_id, override_rate, override_burst)
            if tokens >= 1:
                self._set_bucket(user_id, tokens - 1, now)
                return True
            self._set_bucket(user_id, tokens, now)
            return False

    def get_tokens(self, user_id):
        data = self._get_bucket(user_id)
        if data:
            if isinstance(data, dict):
                return data["tokens"]
            return data[0]
        return self.burst
