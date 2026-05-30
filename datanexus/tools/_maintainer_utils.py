"""
datanexus/tools/_maintainer_utils.py — Shared maintainer history utility.

Extracted for Sprint 6: fetch_package_risk_brief and
fetch_package_maintainer_history both call _fetch_maintainer_history directly.

Sources:
  PyPI: pypi.org/pypi/{name}/json  → maintainers + release timestamps
  npm:  registry.npmjs.org/{name}  → maintainers + time map
  Account age proxy: pypi.org/search/?q=maintainer:{username} (semi-deprecated)
  If account age proxy returns non-200 or 0 results: account_age = "unknown",
  contribute +0.0 to anomaly_score (conservative fallback).
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import quote

import httpx
import pybreaker

from datanexus.tools._circuit_breakers import (
    _pypi_stats_breaker,
    _npm_stats_breaker,
)

log = logging.getLogger("datanexus.tools._maintainer_utils")

_HTTP_HEADERS  = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_TIMEOUT       = httpx.Timeout(5.0, connect=4.0)   # main data fetch
_AGE_TIMEOUT   = 2.0                                 # account-age proxy: best-effort cap

_NOW = lambda: datetime.now(timezone.utc)  # noqa: E731  (testable injection point)


def _days_ago(iso_str: str) -> Optional[int]:
    """Parse an ISO 8601 date string and return how many days ago it was."""
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (_NOW() - dt).days
    except Exception:
        return None


# ── PyPI helpers ───────────────────────────────────────────────────────────────

async def _fetch_pypi_maintainer_data(client: httpx.AsyncClient, package: str) -> dict:
    """Fetch maintainer/release data from PyPI JSON API."""
    url = f"https://pypi.org/pypi/{quote(package, safe='')}/json"
    resp = await client.get(url)
    resp.raise_for_status()
    data = resp.json()
    info = data.get("info", {})
    releases = data.get("releases", {})

    maintainers = []
    # PyPI JSON: maintainers may be in info.maintainer (string) or info.maintainer_email
    raw_maintainer = info.get("maintainer") or ""
    raw_author = info.get("author") or ""
    for name in set(filter(None, [raw_maintainer.strip(), raw_author.strip()])):
        maintainers.append(name)

    # Build a list of (version, upload_time) sorted by time
    releases_list = []
    for version, files in releases.items():
        for f in files:
            upload = f.get("upload_time_iso_8601") or f.get("upload_time") or ""
            if upload:
                releases_list.append((version, upload))
                break
    releases_list.sort(key=lambda x: x[1])

    last_release_iso = releases_list[-1][1] if releases_list else ""
    first_release_iso = releases_list[0][1] if releases_list else ""

    return {
        "maintainers":       maintainers,
        "last_release_iso":  last_release_iso,
        "first_release_iso": first_release_iso,
        "releases_list":     releases_list,
        "source":            "pypi",
    }


async def _fetch_pypi_account_age(client: httpx.AsyncClient, username: str) -> Optional[int]:
    """
    Estimate maintainer account age in days via PyPI search.
    Returns None if the endpoint is unavailable or returns no results.
    +0.0 contribution to anomaly_score on None (conservative fallback).
    """
    try:
        url = f"https://pypi.org/search/?q=maintainer%3A{quote(username, safe='')}"
        resp = await client.get(url, timeout=httpx.Timeout(5.0, connect=3.0))
        if resp.status_code != 200:
            return None
        # Parse earliest upload date as age proxy — semi-deprecated, best effort
        # Look for "released on" in HTML; if not found return None
        text = resp.text
        import re
        dates = re.findall(r'datetime="(\d{4}-\d{2}-\d{2})', text)
        if not dates:
            return None
        earliest = sorted(dates)[0]
        age = _days_ago(earliest)
        return age
    except Exception:
        return None


# ── npm helpers ────────────────────────────────────────────────────────────────

async def _fetch_npm_maintainer_data(client: httpx.AsyncClient, package: str) -> dict:
    """Fetch maintainer/release data from npm registry."""
    url = f"https://registry.npmjs.org/{quote(package, safe='')}"
    resp = await client.get(url)
    resp.raise_for_status()
    data = resp.json()

    maintainers = [m.get("name", "") for m in data.get("maintainers", [])]
    time_map = data.get("time", {})

    release_times = [
        (v, ts) for v, ts in time_map.items()
        if v not in ("created", "modified") and ts
    ]
    release_times.sort(key=lambda x: x[1])

    last_release_iso  = release_times[-1][1] if release_times else ""
    first_release_iso = release_times[0][1] if release_times else ""

    return {
        "maintainers":       maintainers,
        "last_release_iso":  last_release_iso,
        "first_release_iso": first_release_iso,
        "releases_list":     release_times,
        "source":            "npm",
    }


# ── Anomaly scoring ────────────────────────────────────────────────────────────

def _compute_anomaly_score(
    account_age_days: Optional[int],
    ownership_transferred: bool,
    maintainer_count_delta: int,
    release_after_silence: bool,
) -> float:
    """
    Additive anomaly score, clamped to 1.0.

    Factors (SPRINT6_PROMPT.md spec):
      owner_account_age_days < 90  → +0.4
      ownership_transfer_last_90d  → +0.3
      maintainer_count_delta > 1 in 30 days → +0.2
      release_after_6mo_silence    → +0.1
    """
    score = 0.0
    if account_age_days is not None and account_age_days < 90:
        score += 0.4
    if ownership_transferred:
        score += 0.3
    if maintainer_count_delta > 1:
        score += 0.2
    if release_after_silence:
        score += 0.1
    return min(round(score, 2), 1.0)


def _compute_health(
    anomaly_score: float,
    last_release_days: Optional[int],
    ownership_transferred: bool,
    account_age_days: Optional[int],
) -> str:
    """
    Derive maintainer_health label.

    Priority order (first match wins):
      suspicious: anomaly_score > 0.7 OR ownership_transfer OR account < 90 days
      abandoned:  no release in 12+ months AND anomaly_score < 0.7
      stale:      no release in 18+ months AND anomaly_score < 0.7
      healthy:    otherwise
    """
    if anomaly_score > 0.7:
        return "suspicious"
    if ownership_transferred:
        return "suspicious"
    if account_age_days is not None and account_age_days < 90:
        return "suspicious"
    if last_release_days is not None and last_release_days > 365:
        return "abandoned"
    if last_release_days is not None and last_release_days > 548:  # ~18 months
        return "stale"
    return "healthy"


# ── Public utility ─────────────────────────────────────────────────────────────

async def _fetch_maintainer_history(package: str, ecosystem: str) -> dict:
    """
    Fetch and score maintainer health for an npm or PyPI package.

    Returns:
        {
            "maintainer_count":      int,
            "recent_changes":        list[str],
            "ownership_transfers":   list[str],
            "account_ages":          dict[str, int | str],
            "anomaly_score":         float,  # 0.0 – 1.0
            "maintainer_health":     str,    # healthy | stale | abandoned | suspicious
            "last_release_days_ago": int | None,
            "status":                str,    # OK | ERROR | CIRCUIT_OPEN | UNSUPPORTED
        }
    """
    eco = ecosystem.lower()
    if eco not in ("pypi", "npm"):
        return {
            "maintainer_count":      0,
            "recent_changes":        [],
            "ownership_transfers":   [],
            "account_ages":          {},
            "anomaly_score":         0.0,
            "maintainer_health":     "healthy",
            "last_release_days_ago": None,
            "status":                "UNSUPPORTED",
        }

    breaker = _pypi_stats_breaker if eco == "pypi" else _npm_stats_breaker

    async def _fetch_all() -> dict:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True,
        ) as client:
            if eco == "pypi":
                data = await _fetch_pypi_maintainer_data(client, package)
            else:
                data = await _fetch_npm_maintainer_data(client, package)

            maintainers = data["maintainers"]
            last_release_days = _days_ago(data["last_release_iso"])
            first_release_days = _days_ago(data["first_release_iso"])

            # Account age proxy: best-effort, 2s cap so we stay within @with_timeout
            account_ages: dict = {}
            if eco == "pypi" and maintainers:
                try:
                    age = await asyncio.wait_for(
                        _fetch_pypi_account_age(client, maintainers[0]),
                        timeout=_AGE_TIMEOUT,
                    )
                    account_ages[maintainers[0]] = age if age is not None else "unknown"
                except asyncio.TimeoutError:
                    account_ages[maintainers[0]] = "unknown"

            # Detect release after 6-month silence
            releases = data["releases_list"]
            release_after_silence = False
            if len(releases) >= 2:
                penultimate_days = _days_ago(releases[-2][1])
                if penultimate_days is not None and penultimate_days > 180:
                    release_after_silence = True

            # Ownership transfer heuristic: maintainer list changed in last 90 days
            # We don't have historical maintainer data in a single API call,
            # so we proxy via: account age < 90 days is the transfer signal
            ownership_transferred = any(
                v is not None and isinstance(v, int) and v < 90
                for v in account_ages.values()
            )
            ownership_transfers = (
                [maintainers[0]] if ownership_transferred else []
            )

            # Maintainer count delta (we only have current snapshot — delta = 0)
            maintainer_count_delta = 0

            # Get the minimum account age (most suspicious)
            numeric_ages = [v for v in account_ages.values() if isinstance(v, int)]
            min_account_age = min(numeric_ages) if numeric_ages else None

            anomaly_score = _compute_anomaly_score(
                account_age_days=min_account_age,
                ownership_transferred=ownership_transferred,
                maintainer_count_delta=maintainer_count_delta,
                release_after_silence=release_after_silence,
            )
            health = _compute_health(
                anomaly_score=anomaly_score,
                last_release_days=last_release_days,
                ownership_transferred=ownership_transferred,
                account_age_days=min_account_age,
            )

            return {
                "maintainer_count":      len(maintainers),
                "recent_changes":        [],
                "ownership_transfers":   ownership_transfers,
                "account_ages":          account_ages,
                "anomaly_score":         anomaly_score,
                "maintainer_health":     health,
                "last_release_days_ago": last_release_days,
                "status":                "OK",
            }

    try:
        return await breaker.call_async(_fetch_all)
    except pybreaker.CircuitBreakerError:
        log.warning("_fetch_maintainer_history circuit open pkg=%s", package)
        return {
            "maintainer_count":      0,
            "recent_changes":        [],
            "ownership_transfers":   [],
            "account_ages":          {},
            "anomaly_score":         0.0,
            "maintainer_health":     "healthy",
            "last_release_days_ago": None,
            "status":                "CIRCUIT_OPEN",
        }
    except Exception as exc:
        log.warning("_fetch_maintainer_history error pkg=%s: %s", package, exc)
        return {
            "maintainer_count":      0,
            "recent_changes":        [],
            "ownership_transfers":   [],
            "account_ages":          {},
            "anomaly_score":         0.0,
            "maintainer_health":     "healthy",
            "last_release_days_ago": None,
            "status":                "ERROR",
        }
