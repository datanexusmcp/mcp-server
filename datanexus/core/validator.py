"""
datanexus/core/validator.py — Phase 1 deterministic payload validator.

Spec: DataNexus_MCP_Spec_v7_4.docx  Section 13.1 / Phase 1

This is LAYER 1 of the two-layer validation architecture:
  Layer 1 (HERE)   — ingest/cache-write time  — datanexus/core/validator.py
  Layer 2 (Phase 0) — query/response time      — datanexus/tools/t10.py

Both layers run the same T10 Bug 1 + Bug 2 logic independently.
Layer 1 fires when data enters the cache; Layer 2 fires on every response.
Both are needed — different code paths, belt-and-suspenders.

Public API:
  validate_payload(tool_id, raw_data) -> tuple[dict | None, list[str]]
    Returns (cleaned_data, issues_list).
    cleaned_data is None ONLY for General-1 (non_empty_response).
    Never raises. Catches all exceptions.

Rules applied:
  General-1: non_empty_response      — None or {} → (None, ['upstream_empty'])
  General-2: required_fields_present — appends 'missing_required:{field}'
  T04-1:     validate_ein_format     — appends 'malformed_ein'
  T04-2:     validate_financial_figures — appends 'unverified_financials'
  T10-1:     severity_level_from_vector — appends 'severity_derived'
  T10-2:     deduplicate_by_cve_alias  — appends 'pysec_deduplicated:{n}'
  T10-3:     flag_incomplete_records   — appends 'incomplete_records:{n}'
"""

import copy
import json
import logging
import math
import re

log = logging.getLogger("datanexus.core.validator")

# ── Required fields per tool ──────────────────────────────────────────────────
_REQUIRED_FIELDS: dict[str, list[str]] = {
    "T04": ["name"],
    "T10": ["package", "ecosystem"],
}


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def validate_payload(
    tool_id: str,
    raw_data: dict,
) -> "tuple[dict | None, list[str]]":
    """
    Validate and clean a raw upstream payload before caching.

    Args:
        tool_id:  'T04' or 'T10'
        raw_data: parsed upstream response dict (or None)

    Returns:
        (cleaned_data, issues_list)
        cleaned_data is None only when raw_data is None or empty (General-1).
        Never raises.
    """
    try:
        # ── General-1: non_empty_response ─────────────────────────────────────
        if not raw_data:
            return (None, ["upstream_empty"])

        cleaned: dict = copy.deepcopy(raw_data)
        issues:  list[str] = []

        # ── General-2: required_fields_present ────────────────────────────────
        for field in _REQUIRED_FIELDS.get(tool_id, []):
            if field not in cleaned:
                issues.append(f"missing_required:{field}")

        # ── Tool-specific rules ───────────────────────────────────────────────
        if tool_id == "T04":
            cleaned, issues = _apply_t04_rules(cleaned, issues)
        elif tool_id == "T10":
            cleaned, issues = _apply_t10_rules(cleaned, issues)

        return (cleaned, issues)

    except Exception as exc:  # pragma: no cover — safety net
        log.error(json.dumps({
            "event":   "validator_exception",
            "tool_id": tool_id,
            "error":   str(exc),
        }))
        # Return original data with a sentinel issue — never raise
        return (raw_data, ["validator_exception"])


# ══════════════════════════════════════════════════════════════════════════════
# T04 RULES
# ══════════════════════════════════════════════════════════════════════════════

_EIN_RE = re.compile(r"^\d{2}-\d{7}$")


def _apply_t04_rules(
    cleaned: dict,
    issues: list[str],
) -> "tuple[dict, list[str]]":
    """Apply T04-1 and T04-2."""

    # T04-1: validate_ein_format
    ein = cleaned.get("ein", "")
    if ein and not _EIN_RE.match(str(ein)):
        cleaned["malformed_ein"] = True
        issues.append("malformed_ein")

    # T04-2: validate_financial_figures
    #   revenue and expenses must be int or float; flag if present but wrong type
    flagged = False
    for field in ("revenue", "expenses"):
        val = cleaned.get(field)
        if val is not None and not isinstance(val, (int, float)):
            flagged = True
    if flagged:
        cleaned["unverified_financials"] = True
        issues.append("unverified_financials")

    return (cleaned, issues)


# ══════════════════════════════════════════════════════════════════════════════
# T10 RULES
# ══════════════════════════════════════════════════════════════════════════════

def _apply_t10_rules(
    cleaned: dict,
    issues: list[str],
) -> "tuple[dict, list[str]]":
    """Apply T10-1, T10-2, T10-3."""
    vulns: list = cleaned.get("vulns", [])

    # T10-2: deduplicate_by_cve_alias (run before T10-1 — fewer records to process)
    vulns, dedup_count = _val_dedup_pysec_ghsa(vulns)
    if dedup_count:
        issues.append(f"pysec_deduplicated:{dedup_count}")

    # T10-1: severity_level_from_vector
    vulns, sev_fixed = _val_fix_severity_levels(vulns)
    if sev_fixed:
        issues.append("severity_derived")

    # T10-3: flag_incomplete_records
    incomplete_count = 0
    for vuln in vulns:
        summary  = (vuln.get("summary") or "").strip()
        _sev_raw = vuln.get("severity")
        severity = _sev_raw if isinstance(_sev_raw, dict) else {}
        level    = (severity.get("level") or "").strip()
        if not summary and not level:
            vuln["incomplete"] = True
            incomplete_count += 1
    if incomplete_count:
        issues.append(f"incomplete_records:{incomplete_count}")

    cleaned["vulns"] = vulns
    return (cleaned, issues)


# ── T10-1: severity_level_from_vector (ingest-time layer) ────────────────────

def _score_to_level(score: float) -> str:
    """Map CVSS base score to severity level string."""
    if score == 0.0: return "NONE"
    if score < 4.0:  return "LOW"
    if score < 7.0:  return "MEDIUM"
    if score < 9.0:  return "HIGH"
    return "CRITICAL"


def _derive_level_from_vector(vector: str) -> str:
    """
    Derive CVSS severity level from a CVSS vector string.

    Handles:
      - Bare float strings (e.g. "7.5")
      - CVSS 3.x full formula (AV/AC/PR/UI/S/C/I/A)
      - CVSS v2 CIA heuristic fallback

    Returns 'UNKNOWN' when derivation fails.
    """
    if not vector:
        return "UNKNOWN"

    # Fast path: bare numeric score (e.g. stored as "7.5")
    try:
        return _score_to_level(float(vector))
    except (ValueError, TypeError):
        pass

    raw = vector.upper()
    for prefix in ("CVSS:3.1/", "CVSS:3.0/", "CVSS:2.0/"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
            break

    metrics: dict[str, str] = {}
    for part in raw.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v

    if not metrics:
        return "UNKNOWN"

    # CVSS 3.x full base-score formula
    if "AV" in metrics and "AC" in metrics and "S" in metrics:
        _cia    = {"N": 0.00, "L": 0.22, "H": 0.56}
        c_v = _cia.get(metrics.get("C", "N"), 0.0)
        i_v = _cia.get(metrics.get("I", "N"), 0.0)
        a_v = _cia.get(metrics.get("A", "N"), 0.0)
        iss = 1.0 - (1.0 - c_v) * (1.0 - i_v) * (1.0 - a_v)
        if iss == 0.0:
            return "NONE"
        scope_changed = metrics.get("S", "U") == "C"
        impact = (
            7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15.0)
            if scope_changed
            else 6.42 * iss
        )
        _av  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        _ac  = {"L": 0.77, "H": 0.44}
        _pru = {"N": 0.85, "L": 0.62, "H": 0.27}
        _prc = {"N": 0.85, "L": 0.68, "H": 0.50}
        _ui  = {"N": 0.85, "R": 0.62}
        av_v  = _av.get(metrics.get("AV", "L"), 0.55)
        ac_v  = _ac.get(metrics.get("AC", "L"), 0.77)
        pr_v  = (_prc if scope_changed else _pru).get(metrics.get("PR", "N"), 0.85)
        ui_v  = _ui.get(metrics.get("UI", "N"), 0.85)
        exploit    = 8.22 * av_v * ac_v * pr_v * ui_v
        raw_score  = (
            min(1.08 * (impact + exploit), 10.0)
            if scope_changed
            else min(impact + exploit, 10.0)
        )
        base = math.ceil(raw_score * 10.0) / 10.0
        return _score_to_level(base)

    # CVSS v2 simplified CIA heuristic fallback
    _cia2 = {"N": 0.0, "P": 0.275, "C": 0.660}
    c2 = _cia2.get(metrics.get("C", "N"), 0.0)
    i2 = _cia2.get(metrics.get("I", "N"), 0.0)
    a2 = _cia2.get(metrics.get("A", "N"), 0.0)
    return _score_to_level(max(0.0, 10.0 * (c2 + i2 + a2) / 3.0))


def _val_fix_severity_levels(vulns: list) -> "tuple[list, int]":
    """
    T10-1 (ingest-time layer).

    For every vulnerability with severity.level UNKNOWN/missing but a
    cvss_vector present, derive the correct level and mutate in place.

    Returns (vulns, count_fixed).
    """
    fixed = 0
    for vuln in vulns:
        _sev_raw = vuln.get("severity")
        sev      = _sev_raw if isinstance(_sev_raw, dict) else {}
        level    = sev.get("level", "UNKNOWN")
        vector = sev.get("vector", "")
        if level in ("UNKNOWN", "", None) and vector:
            derived = _derive_level_from_vector(vector)
            if derived != "UNKNOWN":
                sev["level"] = derived
                vuln["severity"] = sev
                fixed += 1
                log.info(json.dumps({
                    "fix":       "severity_level_from_vector",
                    "layer":     "ingest_validator",
                    "vuln_id":   vuln.get("id", ""),
                    "old_level": level,
                    "new_level": derived,
                    "vector":    vector,
                }))
    return vulns, fixed


# ── T10-2: deduplicate_by_cve_alias (ingest-time layer) ──────────────────────

def _val_dedup_pysec_ghsa(vulns: list) -> "tuple[list, int]":
    """
    T10-2 (ingest-time layer).

    Suppresses PYSEC records that share a CVE alias with a GHSA record.
    GHSA records carry more complete advisory data — keep GHSA, drop PYSEC.
    Logs each suppression as structured JSON.

    Returns (deduped_vulns, suppressed_count).
    """
    ghsa_cve_aliases: set[str] = set()
    ghsa_by_cve: dict[str, str] = {}
    for v in vulns:
        if v.get("id", "").startswith("GHSA-"):
            for alias in v.get("aliases", []):
                if alias.startswith("CVE-"):
                    ghsa_cve_aliases.add(alias)
                    ghsa_by_cve[alias] = v["id"]

    deduped: list = []
    suppressed = 0
    for v in vulns:
        if v.get("id", "").startswith("PYSEC-"):
            shared = (
                {a for a in v.get("aliases", []) if a.startswith("CVE-")}
                & ghsa_cve_aliases
            )
            if shared:
                shared_alias = next(iter(shared))
                suppressed += 1
                log.info(json.dumps({
                    "fix":          "deduplicate_by_cve_alias",
                    "layer":        "ingest_validator",
                    "suppressed":   v["id"],
                    "kept":         ghsa_by_cve.get(shared_alias, ""),
                    "shared_alias": shared_alias,
                }))
                continue
        deduped.append(v)

    return deduped, suppressed
