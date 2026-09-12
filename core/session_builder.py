"""
Canonical, batch-mode session builder.

This is the implementation actually invoked by pipeline/offline_pipeline.py.
It groups events by (source, src_ip) and splits a group into multiple
sessions whenever the gap between consecutive events exceeds
SESSION_TIMEOUT_SEC, or a session grows past MAX_EVENTS_PER_SESSION.

Note: an alternate timeout-based streaming implementation
(StatefulSessionBuilder) exists under experimental/ — it is not called
by either the offline or the (disconnected) online pipeline. See
docs/PROJECT_STATUS.md for why there are two implementations.
"""

from typing import List

from core.session_object import BehavioralSession

SESSION_TIMEOUT_SEC = 3600
MAX_EVENTS_PER_SESSION = 400
MIN_EVENTS_PER_SESSION = 2


def create_behavioral_sessions(raw_events) -> List[BehavioralSession]:
    groups = {}
    for e in raw_events:
        src_ip = getattr(e, "src_ip", None)
        source = getattr(e, "source", "unknown")
        if not src_ip:
            continue
        groups.setdefault(f"{source}_{src_ip}", []).append(e)

    sessions: List[BehavioralSession] = []

    for session_key, events in groups.items():
        events.sort(key=lambda x: x.timestamp)
        first_event = events[0]

        session = BehavioralSession(
            session_id=f"sess_{session_key}",
            src_ip=getattr(first_event, "src_ip", "unknown"),
        )
        session.source = getattr(first_event, "source", "unknown")

        count = 0
        for i, event in enumerate(events):
            if i > 0:
                gap = (event.timestamp - events[i - 1].timestamp).total_seconds()
                if gap > SESSION_TIMEOUT_SEC or count >= MAX_EVENTS_PER_SESSION:
                    if count >= MIN_EVENTS_PER_SESSION:
                        sessions.append(session)
                    session = BehavioralSession(
                        session_id=f"sess_{session_key}_{i}",
                        src_ip=session.src_ip,
                    )
                    session.source = event.source
                    count = 0

            session.update(event)
            count += 1

        if count >= MIN_EVENTS_PER_SESSION:
            sessions.append(session)

    return sessions
