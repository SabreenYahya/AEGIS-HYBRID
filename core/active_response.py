"""
Active response: optionally issue an iptables DROP rule for a source IP
classified as HIGH/CRITICAL by the fusion engine.

SAFETY MODEL (all three gates must pass before any real firewall change):

  1. config.settings.ENABLE_ACTIVE_RESPONSE must be True.
     Default: False. This is a lab research artifact, not a production
     IPS — see SECURITY.md.
  2. The target IP must fall inside one of
     config.settings.ACTIVE_RESPONSE_ALLOWED_CIDRS.
     Default: empty list, i.e. nothing is ever in-scope until you
     explicitly declare your lab subnet.
  3. config.settings.ACTIVE_RESPONSE_DRY_RUN must be False.
     Default: True — the intended action is logged, not executed.

Every decision (blocked, denied by allowlist, dry-run, disabled) is
logged so the audit trail exists even when nothing was actually
executed. There is still no automatic rollback/unblock mechanism —
that remains a manual operational step (see docs/PROJECT_STATUS.md).
"""

import ipaddress
import logging
import subprocess
import time
from collections import deque
from threading import Lock

from config import settings

logger = logging.getLogger("aegis.active_response")

_BLOCKED_IPS: set = set()
_IP_COOLDOWN: dict = {}
_COOLDOWN_SECONDS = 30
_LOCK = Lock()


def _is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _is_in_allowlist(ip: str) -> bool:
    if not settings.ACTIVE_RESPONSE_ALLOWED_CIDRS:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in settings.ACTIVE_RESPONSE_ALLOWED_CIDRS:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            logger.warning("Invalid CIDR in ACTIVE_RESPONSE_ALLOWED_CIDRS: %s", cidr)
    return False


def _execute_block(ip: str) -> bool:
    """Runs only after all three safety gates in the module docstring
    have passed. Requires passwordless sudo for this exact command to
    be pre-provisioned on the host (out of scope of this repo).

    Returns True only if the iptables command exited with status 0.
    check=False is intentional (we do not want a non-zero exit to
    raise) but that means the exit status must be inspected explicitly
    rather than assumed successful."""
    try:
        result = subprocess.run(
            ["sudo", "-n", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )
        if result.returncode == 0:
            logger.warning("ACTIVE RESPONSE EXECUTED: blocked %s", ip)
            return True
        logger.error(
            "iptables exited with non-zero status %d for %s", result.returncode, ip
        )
        return False
    except (subprocess.SubprocessError, OSError) as exc:
        logger.error("Active response execution failed for %s: %s", ip, exc)
        return False


def request_block(ip: str, severity_level: str) -> str:
    """
    Evaluate (and, only if fully authorized, execute) a block request.

    Returns one of: "disabled", "severity_below_threshold", "invalid_ip",
    "not_in_allowlist", "cooldown", "already_blocked", "dry_run",
    "execution_failed", "executed".
    This return value is what should be recorded in the detection
    output — never assume a block happened just because this was called.
    "executed" is only returned once the underlying iptables command
    has confirmed success (see _execute_block); otherwise
    "execution_failed" is returned and the IP is NOT added to
    blocked_ips().
    """
    if not settings.ENABLE_ACTIVE_RESPONSE:
        logger.info("Active response disabled (ENABLE_ACTIVE_RESPONSE=false); ip=%s", ip)
        return "disabled"

    if severity_level not in ("HIGH", "CRITICAL"):
        return "severity_below_threshold"

    if not _is_valid_ip(ip):
        logger.warning("Active response requested for invalid IP: %r", ip)
        return "invalid_ip"

    if not _is_in_allowlist(ip):
        logger.info("IP %s not in ACTIVE_RESPONSE_ALLOWED_CIDRS; refusing", ip)
        return "not_in_allowlist"

    with _LOCK:
        now = time.time()
        if ip in _IP_COOLDOWN and now - _IP_COOLDOWN[ip] < _COOLDOWN_SECONDS:
            return "cooldown"
        _IP_COOLDOWN[ip] = now

        if ip in _BLOCKED_IPS:
            return "already_blocked"

        if settings.ACTIVE_RESPONSE_DRY_RUN:
            logger.warning("DRY RUN — would block %s (severity=%s)", ip, severity_level)
            return "dry_run"

    # Execute outside the lock (subprocess call may block up to its
    # timeout). The IP is only recorded as blocked if iptables
    # confirmed success — never optimistically before that.
    if not _execute_block(ip):
        return "execution_failed"

    with _LOCK:
        _BLOCKED_IPS.add(ip)

    return "executed"


def blocked_ips() -> list:
    with _LOCK:
        return sorted(_BLOCKED_IPS)
