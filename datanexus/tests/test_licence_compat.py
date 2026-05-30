"""
Unit tests for datanexus/tools/_licence_compat.py — PRE-2 requirement.

Tests:
  test_gpl3_apache_is_conflict
  test_mit_apache_is_compatible
  test_unknown_pair_returns_unknown
  test_symmetric_lookup
"""

from datanexus.tools._licence_compat import get_compatibility, STATIC_LICENCES


def test_gpl3_apache_is_conflict():
    """GPL-3.0-only + Apache-2.0 must be CONFLICT (ASF position 2007)."""
    assert get_compatibility("GPL-3.0-only", "Apache-2.0") == "CONFLICT"


def test_gpl2_apache_is_conflict():
    """GPL-2.0-only + Apache-2.0 must be CONFLICT (ASF position 2007)."""
    assert get_compatibility("GPL-2.0-only", "Apache-2.0") == "CONFLICT"


def test_agpl_mit_is_conflict():
    """AGPL-3.0-or-later + MIT must be CONFLICT in proprietary context."""
    assert get_compatibility("AGPL-3.0-or-later", "MIT") == "CONFLICT"


def test_gpl_version_incompatibility():
    """GPL-2.0-only + GPL-3.0-only must be CONFLICT (version incompatibility)."""
    assert get_compatibility("GPL-2.0-only", "GPL-3.0-only") == "CONFLICT"


def test_eupl_gpl3_is_conflict():
    """EUPL-1.1 + GPL-3.0-only must be CONFLICT."""
    assert get_compatibility("EUPL-1.1", "GPL-3.0-only") == "CONFLICT"


def test_mit_apache_is_compatible():
    """MIT + Apache-2.0 must be COMPATIBLE."""
    assert get_compatibility("MIT", "Apache-2.0") == "COMPATIBLE"


def test_mit_bsd2_is_compatible():
    assert get_compatibility("MIT", "BSD-2-Clause") == "COMPATIBLE"


def test_mit_bsd3_is_compatible():
    assert get_compatibility("MIT", "BSD-3-Clause") == "COMPATIBLE"


def test_mit_isc_is_compatible():
    assert get_compatibility("MIT", "ISC") == "COMPATIBLE"


def test_apache_bsd2_is_compatible():
    assert get_compatibility("Apache-2.0", "BSD-2-Clause") == "COMPATIBLE"


def test_lgpl_gpl2_is_compatible():
    """LGPL-2.1-or-later + GPL-2.0-or-later must be COMPATIBLE."""
    assert get_compatibility("LGPL-2.1-or-later", "GPL-2.0-or-later") == "COMPATIBLE"


def test_unknown_pair_returns_unknown():
    """A pair not in the table must return UNKNOWN."""
    assert get_compatibility("SSPL-1.0", "MIT") == "UNKNOWN"
    assert get_compatibility("BSL-1.1", "Apache-2.0") == "UNKNOWN"


def test_symmetric_lookup():
    """get_compatibility(A, B) must equal get_compatibility(B, A) for all pairs."""
    pairs = [
        ("MIT", "Apache-2.0"),
        ("GPL-3.0-only", "Apache-2.0"),
        ("AGPL-3.0-or-later", "MIT"),
        ("EUPL-1.1", "GPL-3.0-only"),
        ("LGPL-2.1-or-later", "GPL-2.0-or-later"),
        ("GPL-2.0-only", "GPL-3.0-only"),
        ("SSPL-1.0", "MIT"),    # UNKNOWN pair — still must be symmetric
    ]
    for a, b in pairs:
        assert get_compatibility(a, b) == get_compatibility(b, a), (
            f"Asymmetric result for ({a}, {b})"
        )


def test_same_licence_mit_is_compatible():
    """MIT + MIT must be COMPATIBLE."""
    assert get_compatibility("MIT", "MIT") == "COMPATIBLE"


def test_static_bundle_contains_required_ids():
    """STATIC_LICENCES must contain the minimum required SPDX IDs."""
    required = {"MIT", "Apache-2.0", "GPL-2.0-only", "GPL-3.0-only",
                "LGPL-2.1-or-later", "AGPL-3.0-or-later", "MPL-2.0",
                "BSD-2-Clause", "BSD-3-Clause", "ISC"}
    for spdx_id in required:
        assert spdx_id in STATIC_LICENCES, f"{spdx_id} missing from STATIC_LICENCES"


def test_agpl_plain_english_mentions_incompatible():
    """AGPL entries must explicitly note INCOMPATIBLE for proprietary SaaS."""
    for spdx_id in ("AGPL-3.0-only", "AGPL-3.0-or-later"):
        entry = STATIC_LICENCES[spdx_id]
        assert "INCOMPATIBLE" in entry["plain_english"], (
            f"{spdx_id} plain_english must mention INCOMPATIBLE"
        )
        assert "INCOMPATIBLE" in entry["tldr"], (
            f"{spdx_id} tldr must mention INCOMPATIBLE"
        )
