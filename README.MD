# Smart Limiter API

A lightweight rate‑limited API server built with Flask. It implements a token bucket algorithm to control how many requests a client can make in a given time. This project is a learning exercise in API design, middleware, and concurrency.

## Project Structure

```
.
├── app.py                 # Flask application and rate limiting middleware
├── rate_limiter.py        # Token bucket algorithm implementation
├── requirements.txt       # Python dependencies
├── .env                   # Environment variables (RATE, BURST)
├── .gitignore            # Git ignore rules
└── README.MD             # This file
```

## Overview

Smart Limiter API exposes a single endpoint `/hello` that returns a friendly greeting. Before each request, a middleware checks the client's IP address against an in‑memory token bucket. If the client has a token available, the request proceeds; otherwise, a `429 Too Many Requests` response is returned with a `Retry-After` header.

The rate limit is configurable via environment variables:
- `RATE`: tokens added per second (default 5)
- `BURST`: maximum tokens a client can accumulate (default 10)

This simple design demonstrates core concepts of API rate limiting and can serve as a foundation for more advanced projects.

## Features

- Token bucket rate limiting per IP address
- Configurable rate and burst values
- Thread‑safe in‑memory storage (no external database required)
- Returns proper HTTP 429 status with `Retry-After` header when rate limit exceeded
- Simple test script to simulate concurrent requests

## Tech Stack

- Python 3.8+
- Flask (web framework)
- python-dotenv (environment variable management)
- threading (for concurrency control)

## Setup

### Prerequisites

- Python 3.8 or higher installed on your system
- Git (optional, for cloning)

### Installation

1. Clone the repository (or download the source):
   ```bash
   git clone https://github.com/VishaliniSaravanan/Rate-Limiter.git
   cd Rate-Limiter
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. Install dependencies:

   ```bash
   pip install flask python-dotenv
   ```

4. Create a `.env` file in the project root to override default settings (optional):

   ```text
   RATE=5
   BURST=10
   ```

## Usage

Start the Flask development server:

```bash
python app.py
```

The server will run at `http://127.0.0.1:5000`. Open your browser or use a tool like curl to test the endpoint:

```bash
curl http://127.0.0.1:5000/hello
```

Expected response:

```json
{"message":"Hello, world!"}
```

## Testing the Rate Limiter

Because the project does not include an automated test script, you can manually verify the rate limiter using curl or a load testing tool like Apache Bench.

### Quick Test with curl

Open two terminals. In the first, run the server. In the second, send rapid requests in a loop.

**Windows Command Prompt:**
```bash
for /l %i in (1,1,20) do curl http://127.0.0.1:5000/hello
```

**macOS/Linux:**
```bash
for i in {1..20}; do curl http://127.0.0.1:5000/hello; done
```

You'll see that after the first few successful requests, the server starts returning 429 errors.

### Load Testing with Apache Bench

If you have Apache Bench (ab) installed, you can simulate many concurrent requests:

```bash
ab -n 30 -c 15 http://127.0.0.1:5000/hello
```

- `-n 30`: total of 30 requests
- `-c 15`: 15 requests sent concurrently

In the output, look for **Non-2xx responses** – this count shows how many requests were blocked by the rate limiter.

#### Installing Apache Bench on Windows

To install Apache Bench on Windows:
1. Download the Apache binaries from [Apache Lounge](https://apachelounge.com/download/)
2. Extract `ab.exe` from the `bin` folder
3. Run it from that folder or add the folder to your `PATH` environment variable
