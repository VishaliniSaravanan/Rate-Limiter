import time
import threading


class TokenBucket:
    def __init__(self, rate, burst):
        self.rate = rate
        self.burst = burst
        self.buckets = {}
        self.lock = threading.Lock()

    def _refill(self, user_id):
        now = time.time()
        tokens, last_refill = self.buckets.get(user_id, (self.burst, now))

        elapsed = now - last_refill
        tokens = min(self.burst, tokens + elapsed * self.rate)

        self.buckets[user_id] = (tokens, now)
        return tokens

    def allow_request(self, user_id):
        with self.lock:
            tokens = self._refill(user_id)

            if tokens >= 1:
                self.buckets[user_id] = (tokens - 1, self.buckets[user_id][1])
                return True

            return False
