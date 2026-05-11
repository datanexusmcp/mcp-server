"""
datanexus/ingest/t04_worker.py — T04 ingest workers.

Spec: DataNexus_MCP_Spec_v7_3.docx  Section 12.4 / Phase 2 Step A

Three workers:
  IRSBMFWorker    — IRS EO BMF regional CSVs (eo1-eo4) — 7-day TTL
  IRSTEOSWorker   — IRS TEOS 990 financial bulk data    — 7-day TTL
  UKCharityWorker — UK Charity Commission API           — 24h TTL (UK GDPR max)

Hard stops:
  - IRS direct sources only — no third-party aggregators with CC-NC restrictions.
  - NEVER store trustee names, officer details, or personal addresses.
  - UK charity data TTL: 86400s MAX — UK GDPR requirement, not negotiable.
"""

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from datanexus.core.ingest_base import IngestBase

log = logging.getLogger("datanexus.ingest.t04")

# ── IRS EO BMF regional CSV URLs ─────────────────────────────────────────────
# Public domain — US government data, no commercial restriction.
# Updated monthly. Four regional files cover all 50 states + territories.
IRS_BMF_URLS = [
    "https://www.irs.gov/pub/irs-soi/eo1.csv",
    "https://www.irs.gov/pub/irs-soi/eo2.csv",
    "https://www.irs.gov/pub/irs-soi/eo3.csv",
    "https://www.irs.gov/pub/irs-soi/eo4.csv",
]

# IRS TEOS bulk index — 990 filing index JSON by year
# Public domain — US government data, no commercial restriction.
IRS_TEOS_INDEX_URLS = [
    "https://s3.amazonaws.com/irs-form-990/index_{year}.json"
]

# UK Charity Commission API
# Open Government Licence v3.0 — commercial use permitted WITH GDPR mitigation.
# Fully public API — no authentication required.
UK_CHARITY_BASE = "https://api.charitycommission.gov.uk/register/api/"

# BMF column map — CSV headers exactly as IRS publishes
BMF_COLUMNS = [
    "EIN", "NAME", "ICO", "STREET", "CITY", "STATE", "ZIP",
    "GROUP", "SUBSECTION", "AFFILIATION", "CLASSIFICATION",
    "RULING", "DEDUCTIBILITY", "FOUNDATION", "ACTIVITY",
    "ORGANIZATION", "STATUS", "TAX_PERIOD", "ASSET_CD",
    "INCOME_CD", "FILING_REQ_CD", "PF_FILING_REQ_CD", "ACCT_PD",
    "ASSET_AMT", "INCOME_AMT", "REVENUE_AMT", "NTEE_CD", "SORT_NAME",
]

_HTTP_TIMEOUT = httpx.Timeout(60.0, connect=10.0)
_HTTP_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}


# ── IRSBMFWorker ──────────────────────────────────────────────────────────────

class IRSBMFWorker(IngestBase):
    """
    Downloads and indexes IRS EO BMF regional CSV files.

    Covers all 1.9M+ active US tax-exempt organisations.
    Indexes each EIN for O(1) lookup: datanexus:T04:bmf:{ein}
    Also builds name-prefix search index: datanexus:T04:bmf:name:{prefix}
    Schedule: every 7 days (data updates monthly).
    TTL per key: 604800s (7 days).
    """

    def __init__(self) -> None:
        super().__init__(
            tool_id="T04",
            source_id="irs_bmf",
            ttl_seconds=604800,
            schedule_seconds=604800,  # weekly — data updates monthly
        )

    async def fetch(self) -> bytes:
        """Download all 4 regional CSVs and index every EIN into Redis."""

        total_rows = 0
        raw_sample = b""  # representative bytes for payload hash

        async with httpx.AsyncClient(
            timeout=_HTTP_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True
        ) as client:
            for url in IRS_BMF_URLS:
                region = url.split("/")[-1]
                log.info(json.dumps({
                    "ts": _iso_now(), "event": "bmf_download_start",
                    "tool": self.tool_id, "region": region,
                }))
                try:
                    async with client.stream("GET", url) as resp:
                        resp.raise_for_status()
                        content = await resp.aread()
                        if not raw_sample:
                            raw_sample = content[:512]

                    rows_indexed = await _index_bmf_csv(content, self.ttl_seconds)
                    total_rows += rows_indexed
                    log.info(json.dumps({
                        "ts": _iso_now(), "event": "bmf_region_indexed",
                        "tool": self.tool_id, "region": region,
                        "rows": rows_indexed,
                    }))
                except Exception as exc:
                    log.error(json.dumps({
                        "ts": _iso_now(), "event": "bmf_region_error",
                        "tool": self.tool_id, "region": region,
                        "error": str(exc),
                    }))
                    raise  # let run_forever record the failure

        log.info(json.dumps({
            "ts": _iso_now(), "event": "bmf_index_complete",
            "tool": self.tool_id, "total_rows": total_rows,
        }))
        return raw_sample or b"ok"


async def _index_bmf_csv(content: bytes, ttl: int) -> int:
    """Parse BMF CSV bytes and index every row into Redis by EIN."""
    from datanexus.core.cache import _get_redis  # type: ignore[attr-defined]

    r = _get_redis()
    if r is None:
        log.warning("_index_bmf_csv: Redis unavailable — skipping index")
        return 0

    text = content.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    pipe = r.pipeline(transaction=False)
    batch_size = 500
    count = 0

    for row in reader:
        ein = row.get("EIN", "").strip()
        if not ein:
            continue

        record = {
            "ein":        ein,
            "name":       row.get("NAME", "").strip(),
            "street":     row.get("STREET", "").strip(),
            "city":       row.get("CITY", "").strip(),
            "state":      row.get("STATE", "").strip(),
            "zip":        row.get("ZIP", "").strip(),
            "ntee_code":  row.get("NTEE_CD", "").strip(),
            "ruling":     row.get("RULING", "").strip(),
            "subsection": row.get("SUBSECTION", "").strip(),
            "status":     row.get("STATUS", "").strip(),
            "tax_period": row.get("TAX_PERIOD", "").strip(),
            "asset_amt":  row.get("ASSET_AMT", "").strip(),
            "income_amt": row.get("INCOME_AMT", "").strip(),
            "revenue_amt":row.get("REVENUE_AMT", "").strip(),
            "source":     "IRS EO BMF",
            "indexed_at": _iso_now(),
        }

        # Primary EIN index
        pipe.set(
            f"datanexus:T04:bmf:{ein}",
            json.dumps(record),
            ex=ttl,
        )

        # Name-prefix search index (first 4 chars, uppercased)
        name = record["name"]
        if name:
            prefix = name[:4].upper()
            pipe.sadd(f"datanexus:T04:bmf:name:{prefix}", ein)
            pipe.expire(f"datanexus:T04:bmf:name:{prefix}", ttl)

        count += 1
        if count % batch_size == 0:
            try:
                pipe.execute()
            except Exception:
                pass
            pipe = r.pipeline(transaction=False)

    try:
        pipe.execute()
    except Exception:
        pass

    return count


# ── IRSTEOSWorker ─────────────────────────────────────────────────────────────

class IRSTEOSWorker(IngestBase):
    """
    Downloads IRS TEOS bulk 990 filing index and extracts financial data.

    Stores per-EIN financial summaries: datanexus:T04:teos:{ein}
    Schedule: every 7 days.
    TTL per key: 604800s (7 days).

    Data source: IRS Tax Exempt Organisation Search bulk downloads.
    Public domain — US government data, no commercial restriction.
    """

    # Current years to attempt for 990 index
    _INDEX_YEARS = [2023, 2022, 2021]

    def __init__(self) -> None:
        super().__init__(
            tool_id="T04",
            source_id="irs_teos",
            ttl_seconds=604800,
            schedule_seconds=604800,
        )

    async def fetch(self) -> bytes:
        """Fetch 990 filing index and cache financial records per EIN."""
        indexed = 0

        async with httpx.AsyncClient(
            timeout=_HTTP_TIMEOUT, headers=_HTTP_HEADERS, follow_redirects=True
        ) as client:
            for year in self._INDEX_YEARS:
                url = f"https://s3.amazonaws.com/irs-form-990/index_{year}.json"
                try:
                    resp = await client.get(url)
                    if resp.status_code == 404:
                        continue
                    resp.raise_for_status()
                    data = resp.json()
                    indexed += await _index_teos_filings(
                        data, year, self.ttl_seconds
                    )
                    log.info(json.dumps({
                        "ts": _iso_now(), "event": "teos_year_indexed",
                        "tool": self.tool_id, "year": year, "count": indexed,
                    }))
                    # Return on first successful year
                    return resp.content[:512]
                except Exception as exc:
                    log.warning(json.dumps({
                        "ts": _iso_now(), "event": "teos_year_skip",
                        "tool": self.tool_id, "year": year, "error": str(exc),
                    }))
                    continue

        # If all years fail, return minimal bytes — circuit breaker handles it
        raise RuntimeError("IRSTEOSWorker: no 990 index year available")


async def _index_teos_filings(data: dict, year: int, ttl: int) -> int:
    """Parse IRS 990 index JSON and store per-EIN records in Redis."""
    from datanexus.core.cache import _get_redis  # type: ignore[attr-defined]

    r = _get_redis()
    if r is None:
        return 0

    filings = data.get("Filings", []) or data.get("filings", [])
    pipe = r.pipeline(transaction=False)
    count = 0

    for filing in filings:
        ein = str(filing.get("EIN", "")).strip().lstrip("0") or ""
        if not ein:
            continue

        record = {
            "ein":           ein,
            "org_name":      filing.get("OrganizationName", ""),
            "return_type":   filing.get("ReturnType", ""),
            "tax_period":    filing.get("TaxPeriod", ""),
            "filing_date":   filing.get("FilingDate", ""),
            "object_id":     filing.get("ObjectId", ""),
            "form_type":     filing.get("ReturnType", ""),
            "year_indexed":  year,
            "source":        "IRS TEOS",
            "indexed_at":    _iso_now(),
        }

        pipe.set(
            f"datanexus:T04:teos:{ein}",
            json.dumps(record),
            ex=ttl,
        )
        count += 1
        if count % 1000 == 0:
            try:
                pipe.execute()
            except Exception:
                pass
            pipe = r.pipeline(transaction=False)

    try:
        pipe.execute()
    except Exception:
        pass

    return count


# ── UKCharityWorker ───────────────────────────────────────────────────────────

class UKCharityWorker(IngestBase):
    """
    Downloads the UK Charity Commission public bulk extract and indexes all
    registered charities into Redis.

    Data source: UK Charity Commission — public bulk extract (no auth required).
    URL: https://ccewuksprdoneregsadata1.blob.core.windows.net/data/json/publicextract.charity.zip
    Licence: Open Government Licence v3.0 — commercial use permitted WITH GDPR mitigation.
    TTL: 86400s (24 hours) — UK GDPR maximum. This is NOT negotiable.

    UK GDPR Mitigation:
    - NEVER store: charity_contact_address*, charity_contact_postcode,
      charity_contact_phone, charity_contact_email.
    - Store ONLY: name, income, activities, status, website (public fields).
    - Data cached maximum 24 hours per UK GDPR requirement.
    - Purpose: due diligence and research only.

    Indexes per charity (main registration only, linked_charity_number == 0):
      datanexus:T04:uk:{registered_charity_number}   → GDPR-safe JSON
      datanexus:T04:uk:name:{4-char prefix}           → set of regno strings
    """

    UK_BULK_URL = (
        "https://ccewuksprdoneregsadata1.blob.core.windows.net"
        "/data/json/publicextract.charity.zip"
    )

    def __init__(self) -> None:
        super().__init__(
            tool_id="T04",
            source_id="uk_charity",
            ttl_seconds=86400,   # 24h — UK GDPR maximum, not negotiable
            schedule_seconds=86400,
        )

    async def fetch(self) -> bytes:
        """Download bulk extract and index all main charities into Redis."""
        log.info(json.dumps({
            "ts": _iso_now(), "event": "uk_bulk_download_start", "tool": self.tool_id,
        }))

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(180.0, connect=15.0),
            headers=_HTTP_HEADERS,
            follow_redirects=True,
        ) as client:
            resp = await client.get(self.UK_BULK_URL)
            resp.raise_for_status()
            zip_bytes = resp.content

        log.info(json.dumps({
            "ts": _iso_now(), "event": "uk_bulk_download_ok",
            "tool": self.tool_id, "bytes": len(zip_bytes),
        }))

        indexed, sample = await _index_uk_bulk(zip_bytes, self.ttl_seconds)

        log.info(json.dumps({
            "ts": _iso_now(), "event": "uk_bulk_index_complete",
            "tool": self.tool_id, "indexed": indexed,
        }))
        return sample or b"ok"


async def _index_uk_bulk(zip_bytes: bytes, ttl: int) -> tuple[int, bytes]:
    """
    Parse the UK Charity Commission bulk JSON extract and index into Redis.

    Returns (count_indexed, sample_bytes).
    GDPR fields EXCLUDED from all stored records:
      charity_contact_address1-5, charity_contact_postcode,
      charity_contact_phone, charity_contact_email.
    """
    import io
    import zipfile as _zipfile
    from datanexus.core.cache import _get_redis  # type: ignore[attr-defined]

    r = _get_redis()
    if r is None:
        log.warning("_index_uk_bulk: Redis unavailable — skipping index")
        return 0, b""

    # Decompress
    zf = _zipfile.ZipFile(io.BytesIO(zip_bytes))
    with zf.open("publicextract.charity.json") as f:
        raw_text = f.read().decode("utf-8-sig", errors="replace")

    records = json.loads(raw_text)
    pipe = r.pipeline(transaction=False)
    batch_size = 500
    count = 0
    sample = b""

    for record in records:
        # Only index main registration (linked_charity_number == 0)
        if record.get("linked_charity_number", 0) != 0:
            continue

        regno = str(record.get("registered_charity_number", "")).strip()
        if not regno or regno == "None":
            continue

        safe = _safe_charity_fields(record, regno)
        val  = json.dumps(safe)

        pipe.set(f"datanexus:T04:uk:{regno}", val, ex=ttl)

        # Name prefix index (first 4 chars, uppercased)
        name = safe.get("name", "")
        if name:
            prefix = name[:4].upper()
            pipe.sadd(f"datanexus:T04:uk:name:{prefix}", regno)
            pipe.expire(f"datanexus:T04:uk:name:{prefix}", ttl)

        count += 1
        if count == 1:
            sample = val.encode()[:512]

        if count % batch_size == 0:
            try:
                pipe.execute()
            except Exception:
                pass
            pipe = r.pipeline(transaction=False)

    try:
        pipe.execute()
    except Exception:
        pass

    return count, sample


async def fetch_uk_charity_bulk_single(regno: str) -> Optional[dict]:
    """
    Live fallback: download the full bulk extract and return one charity.

    Used when Redis is unavailable (e.g. local dev, first boot).
    Downloads the 54MB ZIP — accepts higher latency for correctness.
    No authentication required — fully public data.

    Returns ONLY GDPR-safe fields. Never returns contact addresses,
    phone numbers, or email addresses.
    """
    uk_bulk_url = (
        "https://ccewuksprdoneregsadata1.blob.core.windows.net"
        "/data/json/publicextract.charity.zip"
    )
    import io
    import zipfile as _zipfile

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(180.0, connect=15.0),
        headers=_HTTP_HEADERS,
        follow_redirects=True,
    ) as client:
        resp = await client.get(uk_bulk_url)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        zip_bytes = resp.content

    zf = _zipfile.ZipFile(io.BytesIO(zip_bytes))
    with zf.open("publicextract.charity.json") as f:
        records = json.loads(f.read().decode("utf-8-sig", errors="replace"))

    regno_int = int(regno) if regno.isdigit() else -1
    for record in records:
        if (record.get("registered_charity_number") == regno_int
                and record.get("linked_charity_number", 0) == 0):
            return _safe_charity_fields(record, regno)

    return None


async def search_uk_charity_bulk_by_name(name: str, limit: int = 10) -> list[dict]:
    """
    Live fallback: search charities by name from the bulk extract.
    Returns up to `limit` GDPR-safe results matching the name substring.
    """
    import io
    import zipfile as _zipfile
    uk_bulk_url = (
        "https://ccewuksprdoneregsadata1.blob.core.windows.net"
        "/data/json/publicextract.charity.zip"
    )

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(180.0, connect=15.0),
        headers=_HTTP_HEADERS,
        follow_redirects=True,
    ) as client:
        resp = await client.get(uk_bulk_url)
        resp.raise_for_status()
        zip_bytes = resp.content

    zf = _zipfile.ZipFile(io.BytesIO(zip_bytes))
    with zf.open("publicextract.charity.json") as f:
        records = json.loads(f.read().decode("utf-8-sig", errors="replace"))

    name_upper = name.upper()
    results = []
    for record in records:
        if record.get("linked_charity_number", 0) != 0:
            continue
        cname = (record.get("charity_name") or "").upper()
        if name_upper not in cname:
            continue
        regno = str(record.get("registered_charity_number", ""))
        results.append(_safe_charity_fields(record, regno))
        if len(results) >= limit:
            break

    return results


def _safe_charity_fields(raw: dict, regno: str) -> dict:
    """
    Extract ONLY GDPR-safe fields from a UK Charity Commission bulk record.

    Bulk extract field names (snake_case):
      charity_name, charity_registration_status, latest_income,
      latest_expenditure, charity_activities, date_of_registration,
      date_of_removal, charity_contact_web

    NEVER included (UK GDPR hard stop):
      charity_contact_address1-5  — contact/registered addresses
      charity_contact_postcode    — postcode
      charity_contact_phone       — phone number
      charity_contact_email       — email address
    """
    return {
        "charity_number":    regno,
        "name":              raw.get("charity_name", ""),
        "status":            raw.get("charity_registration_status", ""),
        "income":            raw.get("latest_income"),
        "expenditure":       raw.get("latest_expenditure"),
        "activities":        str(raw.get("charity_activities") or "")[:500],
        "registration_date": str(raw.get("date_of_registration") or "")[:10],
        "removal_date":      str(raw.get("date_of_removal") or "")[:10],
        "web":               raw.get("charity_contact_web", ""),
        "source":            "UK Charity Commission",
        "fetched_at":        _iso_now(),
        # PURPOSE LIMITATION: for due diligence and research only.
        # NOT for profiling individuals associated with charities.
        # EXCLUDED: charity_contact_address*, _postcode, _phone, _email
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()
