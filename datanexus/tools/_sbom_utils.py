"""
datanexus/tools/_sbom_utils.py — Shared SBOM parsing utilities.

Extracted from security_stateful.py (Sprint 8B) so audit_sbom_license_policy
and other tools can reuse the same parser without importing from a tool module.

Public API:
  extract_purls(sbom_str)  → (list[str], format_name)
  parse_purl(purl)         → (name, ecosystem, version) | None
  extract_components(sbom_str) → list[dict]  (name/version/ecosystem dicts)
"""

import json
import logging
from typing import Optional

log = logging.getLogger("datanexus.tools._sbom_utils")


def extract_purls(sbom_str: str) -> tuple[list[str], str]:
    """
    Parse a CycloneDX or SPDX JSON SBOM and return (purls, format_name).
    Raises ValueError if format is unrecognised or no components found.
    """
    try:
        raw = json.loads(sbom_str)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc

    if raw.get("bomFormat") == "CycloneDX":
        return _extract_cyclonedx_purls(raw), "CycloneDX"
    if raw.get("spdxVersion", "").startswith("SPDX-"):
        return _extract_spdx_purls(sbom_str), "SPDX"

    raise ValueError("Unrecognised SBOM format — expected CycloneDX or SPDX JSON.")


def extract_components(sbom_str: str) -> tuple[list[dict], str]:
    """
    Parse SBOM and return (components, format_name).
    Each component is a dict with name/version/ecosystem keys.
    Raises ValueError on malformed input.
    """
    purls, fmt = extract_purls(sbom_str)
    components = []
    for purl in purls:
        parsed = parse_purl(purl)
        if parsed:
            name, ecosystem, version = parsed
            components.append({"name": name, "version": version, "ecosystem": ecosystem})
    return components, fmt


def parse_purl(purl: str) -> Optional[tuple[str, str, str]]:
    """
    Parse a Package URL into (name, ecosystem, version).
    Supports pkg:pypi/*, pkg:npm/*, pkg:cargo/*, pkg:golang/*, pkg:maven/*.
    Returns None for unsupported types.
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    rest = purl[4:]
    slash = rest.find("/")
    if slash < 0:
        return None
    ptype = rest[:slash].lower()
    remainder = rest[slash + 1:]

    at = remainder.rfind("@")
    if at >= 0:
        name    = remainder[:at]
        version = remainder[at + 1:]
    else:
        name    = remainder
        version = ""

    eco_map = {
        "pypi": "pypi", "npm": "npm", "cargo": "cargo",
        "golang": "go", "maven": "maven", "nuget": "nuget",
    }
    ecosystem = eco_map.get(ptype)
    if not ecosystem:
        return None

    version = version.split("?")[0].split("#")[0]
    name    = name.split("?")[0].split("#")[0]
    return name, ecosystem, version


def _extract_cyclonedx_purls(raw: dict) -> list[str]:
    """Extract PURLs from a CycloneDX BOM dict."""
    try:
        from cyclonedx.model.bom import Bom
        bom = Bom.from_json(data=raw)
        return [str(c.purl) for c in bom.components if c.purl]
    except Exception:
        pass
    # Fallback: manual extraction
    purls = []
    for comp in raw.get("components", []):
        purl = comp.get("purl", "")
        if purl:
            purls.append(purl)
    return purls


def _extract_spdx_purls(sbom_str: str) -> list[str]:
    """Extract PURLs from an SPDX 2.3 JSON SBOM."""
    import tempfile, os
    try:
        from spdx_tools.spdx.parser.parse_anything import parse_file
        with tempfile.NamedTemporaryFile(
            suffix=".spdx.json", mode="w", delete=False, encoding="utf-8"
        ) as f:
            f.write(sbom_str)
            fname = f.name
        try:
            doc = parse_file(fname)
            purls = []
            for pkg in doc.packages:
                for ref in pkg.external_references:
                    if "purl" in str(ref.reference_type).lower():
                        purls.append(ref.locator)
            return purls
        finally:
            try:
                os.unlink(fname)
            except OSError:
                pass
    except Exception:
        pass
    # Fallback: manual extraction from SPDX JSON
    try:
        raw = json.loads(sbom_str)
        purls = []
        for pkg in raw.get("packages", []):
            for ext in pkg.get("externalRefs", []):
                if ext.get("referenceType") == "purl":
                    purls.append(ext.get("referenceLocator", ""))
        return [p for p in purls if p]
    except Exception as exc:
        log.warning("_sbom_utils: SPDX fallback parse failed: %s", exc)
        return []
