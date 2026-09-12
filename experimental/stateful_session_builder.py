"""
Alternate, timeout-based streaming session builder.

Not wired into pipeline/offline_pipeline.py (which uses
core/session_builder.py's batch implementation) and not imported by
any live-capture entry point in this repository either — see
experimental/README.md.
"""

import uuid
from datetime import timedelta

from core.session_object import BehavioralSession


class StatefulSessionBuilder:
    def __init__(self, timeout_minutes: int = 30):
        self.timeout = timedelta(minutes=timeout_minutes)
        self.active_sessions: dict = {}

    def process_events(self, unified_events) -> list:
        completed = []

        for event in unified_events:
            try:
                key = event.get_session_key()
                session = self.active_sessions.get(key)

                if session is not None:
                    idle = event.timestamp - session.last_activity
                    if idle > self.timeout:
                        completed.append(self.active_sessions.pop(key))
                        self._create_session(key, event)
                    else:
                        session.update(event)
                else:
                    self._create_session(key, event)
            except Exception:
                continue

        return completed + list(self.active_sessions.values())

    def _create_session(self, key: str, event) -> None:
        session = BehavioralSession(
            session_id=f"sess_{uuid.uuid4().hex[:10]}", src_ip=event.src_ip
        )
        session.update(event)
        self.active_sessions[key] = session
