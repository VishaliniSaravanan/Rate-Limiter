# RateGuard — ML-Powered API Rate Limiter

A Redis-backed, ML-enhanced rate limiter with a live visual dashboard.

## Architecture

```
app.py              ← Flask app, middleware, SSE broadcaster
rate_limiter.py     ← Redis-backed Token Bucket
ml_classifier.py    ← ML classification engine
static/dashboard.html ← Live visual dashboard
```

## Features

| Feature | How it works |
|---|---|
| Redis backend | Token buckets stored in Redis with TTL. Falls back to in-memory if Redis is down. |
| Bot detection | Analyzes request timing regularity — bots have very low stddev between intervals |
| Abuse classification | Scoring system: rate, burst, blocked count, path diversity, user-agent signals |
| Dynamic limits | Classified users get throttled: Bot → 0.2 req/s, Abusive → 0.5 req/s |
| Spike prediction | Compares 5s burst rate vs 60s average to predict traffic spikes |
| Live dashboard | SSE-powered real-time feed, charts, user classification table |

## User Classifications

- **Normal** — score < 30. Full rate limit applies.
- **Suspicious** — score 30–59. Warning state.
- **Abusive** — score ≥ 60, irregular timing. Heavily throttled.
- **Bot** — score ≥ 60, very regular timing. Near-blocked (0.2 req/s).

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Start Redis (Docker)
docker run -d -p 6379:6379 redis:alpine

# Configure (optional)
cp .env.example .env
# Edit RATE and BURST

# Run
python app.py
```

## Environment Variables

```env
RATE=5          # Tokens refilled per second (default: 5)
BURST=10        # Max burst size / initial tokens (default: 10)
REDIS_URL=redis://localhost:6379
```


## Test with Apache Bench

```bash
# Normal traffic
ab -n 100 -c 5 http://localhost:5000/hello

# High rate (will trigger suspicious/abusive)
ab -n 500 -c 50 http://localhost:5000/hello

# Simulate scraping (many paths)
for path in /hello /items /search /foo /bar /baz; do
  ab -n 20 -c 2 http://localhost:5000$path
done
```

## API Endpoints

| Route | Description |
|---|---|
| `GET /hello` | Sample endpoint |
| `GET /items` | Sample endpoint |
| `GET /search?q=` | Sample endpoint |
| `GET /dashboard` | Live dashboard UI |
| `GET /api/stats` | Global stats JSON |
| `GET /api/users` | All classified users |
| `GET /api/user/<ip>` | Single user profile |
| `GET /api/stream` | SSE live event stream |
