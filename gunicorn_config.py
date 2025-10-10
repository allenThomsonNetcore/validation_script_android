import os

# Get port from environment variable (Render provides this)
port = int(os.environ.get("PORT", 10000))

bind = f"0.0.0.0:{port}"
workers = 4
threads = 2
timeout = 120
keepalive = 5
max_requests = 1000
max_requests_jitter = 50 