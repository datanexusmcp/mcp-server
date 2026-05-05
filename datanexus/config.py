import os
from datetime import datetime, timezone
from typing import Optional

# --- Redis / DB -----------------------------------------------------------
REDIS_URL: str = os.environ.get("DATANEXUS_REDIS_URL", "redis://localhost:6379")

# Set to a postgresql:// URL to enable session persistence and grandfathering.
# Leave empty (default) for local dev — the DB layer degrades gracefully.
DB_URL: str = os.environ.get("DATANEXUS_DB_URL", "")

# --- Free-tier expiry -----------------------------------------------------
# When unset, all sessions are grandfathered (free tier never expires).
# Set to an ISO 8601 UTC datetime to activate expiry, e.g.:
#   FREE_TIER_END_DATE=2025-12-01T00:00:00
# Sessions created before this timestamp remain on the free tier;
# sessions created on or after it are subject to paid-tier enforcement.
_fte_raw: str = os.environ.get("FREE_TIER_END_DATE", "").strip()
FREE_TIER_END_DATE: Optional[datetime] = None
if _fte_raw:
    try:
        _parsed = datetime.fromisoformat(_fte_raw)
        # Treat naive datetimes as UTC
        FREE_TIER_END_DATE = (
            _parsed if _parsed.tzinfo else _parsed.replace(tzinfo=timezone.utc)
        )
    except ValueError as _e:
        import logging as _logging
        _logging.getLogger("datanexus.config").error(
            "Invalid FREE_TIER_END_DATE=%r — must be ISO 8601 (e.g. 2025-12-01T00:00:00). "
            "Treating as unset (all sessions grandfathered). Error: %s",
            _fte_raw, _e,
        )

# --- Auth -----------------------------------------------------------------
DATANEXUS_API_KEY: str = os.environ.get("DATANEXUS_API_KEY", "")

# --- T04 tool config ------------------------------------------------------
T04_TOOL_ID = "T04"
T04_CACHE_TTL = 7 * 24 * 3600  # 7 days — 990 filings are annual

# Upstream base URLs (IRS direct sources only — public domain)
IRS_EFTS_BASE   = "https://efts.irs.gov/LATEST/search-index"
UK_CHARITY_BASE = "https://api.charitycommission.gov.uk/register/api/"
# UK Charity Commission API: fully public, no authentication required.

# --- Security field-length caps (Section 2.2) ----------------------------
MAX_TITLE_LEN = 500
MAX_SUMMARY_LEN = 5_000
MAX_FULLTEXT_LEN = 50_000
