"""
datanexus/ingest/t22_worker.py — T22 Professional Licence Verification ingest worker.

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 5, T22 entry

Worker:
  NPPESWorker — pre-seeds top 100 most-searched NPI specialities.
  Schedule: 86400 seconds (24h)
  TTL:      86400 seconds

The worker pre-fetches commonly accessed specialities so the first real user
request hits cache instead of triggering a live NPPES API call. This is a
best-effort warm-up — failures do not degrade live tool responses.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone

import httpx

from datanexus.core.circuit_breaker import record_failure_sync, record_success_sync
from datanexus.core.ingest_base import IngestBase

log = logging.getLogger("datanexus.ingest.t22")

NPPES_API   = "https://npiregistry.cms.hhs.gov/api/"
T22_TTL     = 86400  # 24h
_SCHEDULE   = 86400  # 24h

_HEADERS = {"User-Agent": "DataNexus MCP/1.0 (datanexusmcp.com)"}
_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

# Top 100 most-searched NPI specialities (NUCC taxonomy descriptions)
# Pre-seeded to warm cache for common tool queries.
TOP_SPECIALITIES = [
    "Internal Medicine",
    "Family Medicine",
    "Nurse Practitioner",
    "Physician Assistant",
    "Psychiatry & Neurology",
    "Obstetrics & Gynecology",
    "Pediatrics",
    "General Surgery",
    "Cardiology",
    "Dermatology",
    "Orthopedic Surgery",
    "Ophthalmology",
    "Anesthesiology",
    "Radiology",
    "Emergency Medicine",
    "Neurology",
    "Urology",
    "Gastroenterology",
    "Pulmonology",
    "Hematology & Oncology",
    "Rheumatology",
    "Endocrinology",
    "Nephrology",
    "Infectious Disease",
    "Allergy & Immunology",
    "Physical Medicine & Rehabilitation",
    "Occupational Therapy",
    "Physical Therapy",
    "Speech Language Pathology",
    "Registered Nurse",
    "Licensed Practical Nurse",
    "Clinical Social Work",
    "Counseling",
    "Psychology",
    "Pharmacy",
    "Dentistry",
    "Oral & Maxillofacial Surgery",
    "Orthodontics",
    "Podiatric Medicine & Surgery",
    "Optometry",
    "Chiropractic",
    "Acupuncture",
    "Hospice and Palliative Medicine",
    "Geriatric Medicine",
    "Pain Medicine",
    "Sleep Medicine",
    "Sports Medicine",
    "Colon & Rectal Surgery",
    "Plastic Surgery",
    "Vascular Surgery",
    "Thoracic Surgery",
    "Hand Surgery",
    "Neurological Surgery",
    "Otolaryngology",
    "Pathology",
    "Nuclear Medicine",
    "Radiation Oncology",
    "Medical Oncology",
    "Surgical Oncology",
    "Transplant Surgery",
    "Critical Care Medicine",
    "Neonatal-Perinatal Medicine",
    "Maternal & Fetal Medicine",
    "Reproductive Endocrinology",
    "Interventional Cardiology",
    "Electrophysiology",
    "Preventive Medicine",
    "Occupational Medicine",
    "Addiction Medicine",
    "Adolescent Medicine",
    "Clinical Pharmacology",
    "Forensic Psychiatry",
    "Geriatric Psychiatry",
    "Child Psychiatry",
    "Medical Genetics",
    "Clinical Neurophysiology",
    "Diagnostic Radiology",
    "Interventional Radiology",
    "Neuroradiology",
    "Cardiovascular Disease",
    "Pulmonary Critical Care",
    "Nephrology & Hypertension",
    "Hepatology",
    "Inflammatory Bowel Disease",
    "Bariatric Medicine",
    "Wound Care",
    "Palliative Care",
    "Clinical Nurse Specialist",
    "Certified Registered Nurse Anesthetist",
    "Certified Nurse Midwife",
    "Home Health Aide",
    "Respiratory Therapist",
    "Radiologic Technologist",
    "Medical Assistant",
    "Dietitian",
    "Audiologist",
    "Genetic Counselor",
    "Prosthetist",
    "Orthotist",
]


class NPPESWorker(IngestBase):
    """
    Pre-seeds NPPES NPI registry data for the top 100 most-searched specialities.

    Fetches up to 10 providers per speciality and stores results in Redis so
    common T22 search queries hit the cache on first call.
    """

    def __init__(self) -> None:
        super().__init__(
            tool_id="T22",
            source_id="nppes",
            ttl_seconds=T22_TTL,
            schedule_seconds=_SCHEDULE,
        )

    async def fetch(self) -> bytes:
        """
        Fetch NPPES data for top specialities. Returns a summary JSON blob
        for the base class to hash and store. Per-speciality cache entries
        are written directly to Redis by the worker.
        """
        fetched = 0
        failed  = 0

        async with httpx.AsyncClient(
            timeout=_TIMEOUT, headers=_HEADERS, follow_redirects=True
        ) as client:
            for speciality in TOP_SPECIALITIES:
                try:
                    results = await _fetch_speciality(client, speciality, limit=10)
                    if results:
                        await _cache_speciality(speciality, results)
                        fetched += 1
                        record_success_sync("nppes")
                    else:
                        log.info(json.dumps({
                            "ts":         _iso_now(),
                            "event":      "nppes_worker_empty_speciality",
                            "speciality": speciality,
                        }))
                except Exception as exc:
                    failed += 1
                    log.warning(json.dumps({
                        "ts":         _iso_now(),
                        "event":      "nppes_worker_fetch_error",
                        "speciality": speciality,
                        "error":      str(exc),
                    }))
                    if failed >= 5:
                        record_failure_sync("nppes")
                    # Continue to next speciality — never crash the worker
                    await asyncio.sleep(1)
                    continue

                # Polite pacing — avoid hammering NPPES
                await asyncio.sleep(0.5)

        summary = {
            "worker":    "NPPESWorker",
            "fetched_at": _iso_now(),
            "specialities_fetched": fetched,
            "specialities_failed":  failed,
            "total_specialities":   len(TOP_SPECIALITIES),
        }
        log.info(json.dumps({**summary, "event": "nppes_worker_complete"}))
        return json.dumps(summary).encode()


async def _fetch_speciality(
    client: httpx.AsyncClient,
    speciality: str,
    limit: int = 10,
) -> list:
    """Fetch up to `limit` providers for a given taxonomy description."""
    resp = await client.get(
        NPPES_API,
        params={
            "taxonomy_description": speciality,
            "version": "2.1",
            "limit":   str(limit),
        },
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("results", [])


async def _cache_speciality(speciality: str, results: list) -> None:
    """Store pre-fetched speciality results in Redis for T22 search queries."""
    from datanexus.core.cache import _get_redis  # type: ignore[attr-defined]
    r = _get_redis()
    if r is None:
        return

    # Store raw normalised list under speciality-keyed cache
    key = f"datanexus:T22:speciality:{speciality.lower().replace(' ', '_')}"
    try:
        r.set(key, json.dumps(results, default=str), ex=T22_TTL)
    except Exception as exc:
        log.warning(json.dumps({
            "ts":    _iso_now(),
            "event": "nppes_worker_cache_error",
            "key":   key,
            "error": str(exc),
        }))


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    import asyncio
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )
    worker = NPPESWorker()
    asyncio.run(worker.run_forever())
