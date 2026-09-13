"""
Standalone Cowrie event ingestion endpoint.

This utility is NOT part of the canonical offline detection pipeline.
It accepts authenticated event payloads and writes normalized Cowrie
records to a local queue/file for later batch processing.

Security properties:
  - Requires a shared-secret API key (X-API-Key header), checked with
    constant-time comparison. Refuses to start without INGEST_API_KEY.
  - Per-client in-memory rate limiting.
  - Bounded LRU dedup cache.
  - Binds to INGEST_API_HOST (default 127.0.0.1).

Still lab-grade: no TLS termination is provided and Flask's development
server is not an appropriate public deployment target.
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
_event_queue: Queue = Queue(maxsize=10000)

_DEDUP_MAX = 50_000
_seen: "OrderedDict[str, None]" = OrderedDict()
_seen_lock = threading.Lock()

_rate_windows: dict = {}
_rate_lock = threading.Lock()
_writer_started = False
_writer_start_lock = threading.Lock()


def _dedup_check_and_add(uid: str) -> bool:
    """Return True if uid was already seen."""
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


def _json_dumps(obj) -> str:
    import json
    return json.dumps(obj)


def _writer_loop() -> None:
    while True:
        event = _event_queue.get()
        try:
            directory = os.path.dirname(LOG_FILE)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(_json_dumps(event) + "\n")
        except OSError as exc:
            logger.error("Failed writing event to %s: %s", LOG_FILE, exc)
        finally:
            _event_queue.task_done()


def _ensure_writer_started() -> None:
    global _writer_started
    if _writer_started:
        return
    with _writer_start_lock:
        if not _writer_started:
            threading.Thread(target=_writer_loop, daemon=True, name="aegis-ingest-writer").start()
            _writer_started = True


@app.before_request
def _auth_and_rate_limit():
    _ensure_writer_started()
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
    settings.require_ingest_api_key()
    _ensure_writer_started()
    logger.warning(
        "Running Flask's built-in server. For anything beyond local testing, "
        "use a WSGI server and TLS-terminating reverse proxy — see SECURITY.md."
    )
    app.run(host=settings.INGEST_API_HOST, port=settings.INGEST_API_PORT, threaded=True)
