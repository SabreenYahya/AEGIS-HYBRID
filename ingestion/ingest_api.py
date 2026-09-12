"""
Cowrie event ingestion endpoint.

Hardened relative to the original prototype:
  - Requires a shared-secret API key (X-API-Key header), checked with
    constant-time comparison. Refuses to start if INGEST_API_KEY is unset.
  - Per-client in-memory rate limiting (INGEST_RATE_LIMIT_PER_MIN).
  - Bounded LRU dedup cache instead of an unbounded set() — the original
    prototype's `seen = set()` grew forever and was an unbounded-memory
    DoS vector under sustained traffic.
  - Binds to INGEST_API_HOST (default 127.0.0.1), not 0.0.0.0, so it is
    not reachable off-host unless explicitly configured to be.

Still lab-grade, not production-grade: no TLS termination here (put a
reverse proxy in front of it if you expose this beyond localhost), and
Flask's development server should not be the final deployment target
(see SECURITY.md and the __main__ block below).
"""

import hmac
import logging
import os
import threading
import time
from collections import OrderedDict, deque
from datetime import datetime, timezone
from queue import Full, Queue

from flask import Flask, jsonify, request

from config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis.ingest_api")

app = Flask(__name__)

LOG_FILE = os.getenv("INGEST_OUTPUT_LOG", "/opt/logs/cowrie.json")
ERROR_LOG = os.getenv("INGEST_ERROR_LOG", "/opt/logs/errors.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

_event_queue: Queue = Queue(maxsize=10000)

# Bounded dedup cache: OrderedDict as a simple LRU, capped at _DEDUP_MAX.
_DEDUP_MAX = 50_000
_seen: "OrderedDict[str, None]" = OrderedDict()
_seen_lock = threading.Lock()

# Per-client sliding-window rate limiting.
_rate_windows: dict = {}
_rate_lock = threading.Lock()


def _dedup_check_and_add(uid: str) -> bool:
    """Returns True if uid was already seen (i.e., this is a duplicate)."""
    if uid is None:
        return False
    with _seen_lock:
        if uid in _seen:
            _seen.move_to_end(uid)
            return True
        _seen[uid] = None
        if len(_seen) > _DEDUP_MAX:
            _seen.popitem(last=False)
        return False


def _rate_limited(client_ip: str) -> bool:
    limit = settings.INGEST_RATE_LIMIT_PER_MIN
    now = time.time()
    with _rate_lock:
        window = _rate_windows.setdefault(client_ip, deque())
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= limit:
            return True
        window.append(now)
        return False


def _require_api_key() -> bool:
    provided = request.headers.get("X-API-Key", "")
    expected = settings.INGEST_API_KEY or ""
    return bool(expected) and hmac.compare_digest(provided, expected)


def _normalize(event: dict) -> dict:
    return {
        "timestamp": event.get("timestamp"),
        "src_ip": event.get("src_ip"),
        "event_type": event.get("event_type"),
        "input": event.get("input"),
        "event_uid": event.get("event_uid"),
        "received_at": datetime.now(timezone.utc).isoformat(),
        "sensor": event.get("sensor", "cowrie"),
    }


def _writer_loop() -> None:
    while True:
        event = _event_queue.get()
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(_json_dumps(event) + "\n")
        except OSError as exc:
            logger.error("Failed writing event to %s: %s", LOG_FILE, exc)
        finally:
            _event_queue.task_done()


def _json_dumps(obj) -> str:
    import json
    return json.dumps(obj)


threading.Thread(target=_writer_loop, daemon=True).start()


@app.before_request
def _auth_and_rate_limit():
    if not _require_api_key():
        logger.warning("Rejected unauthenticated request from %s", request.remote_addr)
        return jsonify({"error": "unauthorized"}), 401
    if _rate_limited(request.remote_addr or "unknown"):
        return jsonify({"error": "rate limit exceeded"}), 429


@app.route("/ingestion/ingest", methods=["POST"])
def ingest():
    data = request.get_json(force=True, silent=True)
    if data is None:
        return jsonify({"error": "invalid or missing JSON body"}), 400

    if isinstance(data, list):
        accepted = 0
        for event in data:
            if not isinstance(event, dict):
                continue
            if _dedup_check_and_add(event.get("event_uid")):
                continue
            try:
                _event_queue.put_nowait(_normalize(event))
                accepted += 1
            except Full:
                logger.warning("Ingestion queue full — dropping remaining batch events")
                break
        return jsonify({"status": "batch accepted", "count": accepted}), 200

    if not isinstance(data, dict):
        return jsonify({"error": "invalid format"}), 400

    if _dedup_check_and_add(data.get("event_uid")):
        return jsonify({"status": "duplicate"}), 200

    try:
        _event_queue.put_nowait(_normalize(data))
    except Full:
        return jsonify({"error": "queue full"}), 503

    return jsonify({"status": "accepted"}), 200


@app.route("/healthz", methods=["GET"])
def healthz():
    """Unauthenticated liveness probe — intentionally exposes no data."""
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    settings.require_ingest_api_key()  # fail fast, not silently unauthenticated
    logger.warning(
        "Running Flask's built-in server. For anything beyond local testing, "
        "run this behind a WSGI server (gunicorn/uwsgi) and a TLS-terminating "
        "reverse proxy — see SECURITY.md."
    )
    app.run(host=settings.INGEST_API_HOST, port=settings.INGEST_API_PORT, threaded=True)
