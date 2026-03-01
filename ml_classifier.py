"""
  Normal     → score < 40   (casual browsing, small ab runs)
  Suspicious → score 40–69  (moderate ab, repeated requests)
  Abusive    → score 70–89  (very high rate, many blocks)
  Bot        → score 90+    (abusive + robot-like timing regularity)
"""

import time
import threading
import math
import os
from collections import deque, defaultdict

try:
    import redis, json
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
    r = redis.from_url(REDIS_URL, decode_responses=True)
    r.ping()
    REDIS_AVAILABLE = True
except Exception:
    REDIS_AVAILABLE = False

NORMAL     = "normal"
SUSPICIOUS = "suspicious"
ABUSIVE    = "abusive"
BOT        = "bot"

# ── Thresholds (tuned so small traffic = normal) ──────────
WINDOW_SECONDS          = 60
SUSPICIOUS_RATE         = 40   # req/min to become suspicious
ABUSIVE_RATE            = 100  # req/min to become abusive
BURST_WINDOW            = 5    # seconds
BURST_THRESHOLD         = 15   # requests in 5s → suspicious burst
BOT_MIN_REQUESTS        = 20   # need at least this many before timing analysis
BOT_REGULARITY_THRESHOLD = 0.08  # stddev/mean below this = bot-like
SCRAPING_PATH_THRESHOLD = 20   # unique paths → scraping
BLOCK_SUSPICIOUS        = 3    # blocked this many times → suspicious
BLOCK_ABUSIVE           = 8    # blocked this many times → abusive contribution

# Points awarded per signal
POINTS = {
    "rate_suspicious":  20,   # 40–100 req/min
    "rate_abusive":     40,   # 100+ req/min
    "burst":            20,   # 15+ req in 5s
    "bot_timing":       35,   # very regular intervals
    "scraping":         15,   # many unique paths
    "block_few":        10,   # 3–7 blocks
    "block_many":       25,   # 8+ blocks
    "bot_ua":           10,   # curl/wget/python UA (lower — ab is legitimate testing)
    "no_ua":             5,   # missing UA
}


class UserProfile:
    def __init__(self):
        self.timestamps  = deque(maxlen=500)
        self.paths       = deque(maxlen=200)
        self.user_agents = set()
        self.blocked_count = 0
        self.classification = NORMAL
        self.score          = 0.0
        self.dynamic_rate   = None
        self.dynamic_burst  = None
        self.active_signals = []   # list of signal keys that fired


class MLClassifier:
    def __init__(self):
        self.profiles         = defaultdict(UserProfile)
        self.lock             = threading.Lock()
        self.global_timestamps = deque(maxlen=2000)
        self.traffic_history  = deque(maxlen=60)
        self._last_tick       = time.time()
        self._tick_count      = 0

    def record_request(self, user_id, path="/", user_agent="", blocked=False):
        now = time.time()
        with self.lock:
            p = self.profiles[user_id]
            p.timestamps.append(now)
            p.paths.append(path)
            if user_agent:
                p.user_agents.add(user_agent[:120])
            if blocked:
                p.blocked_count += 1

            self.global_timestamps.append(now)
            self._tick_count += 1
            if now - self._last_tick >= 1.0:
                self.traffic_history.append(self._tick_count)
                self._tick_count = 0
                self._last_tick  = now

            signals, score = self._score(p, now)
            classification  = self._classify(score, signals)

            p.score          = score
            p.classification = classification
            p.active_signals = signals
            p.dynamic_rate, p.dynamic_burst = self._dynamic_limits(classification)

            if REDIS_AVAILABLE:
                self._persist(user_id, p)

        return classification, score

    # ── Scoring ────────────────────────

    def _score(self, p, now):
        signals = []
        score   = 0.0

        recent_60 = [t for t in p.timestamps if now - t <= WINDOW_SECONDS]
        rate_60   = len(recent_60)

        # Rate signals
        if rate_60 >= ABUSIVE_RATE:
            score += POINTS["rate_abusive"]
            signals.append("rate_abusive")
        elif rate_60 >= SUSPICIOUS_RATE:
            score += POINTS["rate_suspicious"]
            signals.append("rate_suspicious")

        # Burst
        burst = sum(1 for t in p.timestamps if now - t <= BURST_WINDOW)
        if burst >= BURST_THRESHOLD:
            score += POINTS["burst"]
            signals.append("burst")

        # Bot timing — only after enough samples
        if len(recent_60) >= BOT_MIN_REQUESTS:
            intervals = [recent_60[i+1] - recent_60[i] for i in range(len(recent_60)-1)]
            if intervals:
                mean = sum(intervals) / len(intervals)
                if mean > 0:
                    variance = sum((x-mean)**2 for x in intervals) / len(intervals)
                    stddev   = math.sqrt(variance)
                    cv       = stddev / mean   # coefficient of variation
                    if cv < BOT_REGULARITY_THRESHOLD:
                        score += POINTS["bot_timing"]
                        signals.append("bot_timing")

        # Scraping
        unique_paths = len(set(list(p.paths)))
        if unique_paths >= SCRAPING_PATH_THRESHOLD:
            score += POINTS["scraping"]
            signals.append("scraping")

        # Repeated blocks
        if p.blocked_count >= BLOCK_ABUSIVE:
            score += POINTS["block_many"]
            signals.append("block_many")
        elif p.blocked_count >= BLOCK_SUSPICIOUS:
            score += POINTS["block_few"]
            signals.append("block_few")

        # UA checks — lower weight so a single ab run doesn't auto-flag
        uas = " ".join(p.user_agents).lower()
        if any(k in uas for k in ["curl", "wget", "scrapy", "go-http", "python-urllib", "java/"]):
            score += POINTS["bot_ua"]
            signals.append("bot_ua")
        # ApacheBench is a test tool — only flag it if combined with high rate
        if "apachebench" in uas and rate_60 >= SUSPICIOUS_RATE:
            score += POINTS["bot_ua"]
            if "bot_ua" not in signals:
                signals.append("bot_ua")

        if any(ua.strip() == "" for ua in p.user_agents):
            score += POINTS["no_ua"]
            signals.append("no_ua")

        return signals, round(min(score, 100), 1)

    def _classify(self, score, signals):
        # Bot requires timing regularity signal + high score
        if score >= 70 and "bot_timing" in signals:
            return BOT
        if score >= 70:
            return ABUSIVE
        if score >= 40:
            return SUSPICIOUS
        return NORMAL

    def _dynamic_limits(self, classification):
        if classification == BOT:
            return 0.2, 1
        if classification == ABUSIVE:
            return 0.5, 2
        if classification == SUSPICIOUS:
            return 3.0, 5
        return None, None

    # ── Public API ───────────────

    def get_profile(self, user_id):
        with self.lock:
            p = self.profiles.get(user_id)
            if not p:
                return None
            return {
                "classification": p.classification,
                "score":          round(p.score, 1),
                "requests_60s":   sum(1 for t in p.timestamps if time.time()-t <= 60),
                "blocked_count":  p.blocked_count,
                "unique_paths":   len(set(list(p.paths))),
                "dynamic_rate":   p.dynamic_rate,
                "dynamic_burst":  p.dynamic_burst,
                "user_agents":    list(p.user_agents)[:3],
                "signals":        p.active_signals,
            }

    def get_all_users(self):
        with self.lock:
            now    = time.time()
            result = []
            for uid, p in self.profiles.items():
                recent = sum(1 for t in p.timestamps if now - t <= 60)
                if recent == 0 and p.classification == NORMAL:
                    continue
                result.append({
                    "user_id":        uid,
                    "classification": p.classification,
                    "score":          round(p.score, 1),
                    "requests_60s":   recent,
                    "blocked_count":  p.blocked_count,
                    "signals":        p.active_signals,
                })
            return sorted(result, key=lambda x: x["score"], reverse=True)

    def get_global_stats(self):
        with self.lock:
            now        = time.time()
            total_60s  = sum(1 for t in self.global_timestamps if now - t <= 60)
            total_5s   = sum(1 for t in self.global_timestamps if now - t <= 5)
            spike_pred = (total_5s * 12) > (total_60s * 1.5) if total_60s > 0 else False

            classifications = defaultdict(int)
            for p in self.profiles.values():
                if sum(1 for t in p.timestamps if now - t <= 60) > 0:
                    classifications[p.classification] += 1

            return {
                "total_requests_60s": total_60s,
                "total_requests_5s":  total_5s,
                "spike_predicted":    spike_pred,
                "classifications":    dict(classifications),
                "traffic_history":    list(self.traffic_history)[-30:],
                "active_users":       len([p for p in self.profiles.values()
                                           if sum(1 for t in p.timestamps if now-t <= 60) > 0]),
            }

    def _persist(self, user_id, p):
        try:
            r.setex(f"ml:user:{user_id}", 3600, json.dumps({
                "classification": p.classification,
                "score":          p.score,
                "blocked_count":  p.blocked_count,
            }))
        except Exception:
            pass
