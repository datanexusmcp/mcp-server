"""
datanexus/tools/_licence_compat.py — Static SPDX licence compatibility table.

Hand-coded from SPDX Annex C, ASF licence policy (2007), and FSF
compatibility notes. No machine-readable SPDX matrix exists (OQ2 resolved).

Lookup: get_compatibility(a, b) → "COMPATIBLE" | "CONFLICT" | "UNKNOWN"
Symmetric: get_compatibility(A, B) == get_compatibility(B, A) always.

Static bundle also serves fetch_licence_analysis as an offline source for
the top-50 SPDX IDs, avoiding rate-limit risk when audit_licence_compatibility
resolves up to 50 packages in parallel.

All risk_level values assume proprietary/commercial use context.
"""

from typing import Literal

CompatResult = Literal["COMPATIBLE", "CONFLICT", "UNKNOWN"]

# ── Compatibility pairs ────────────────────────────────────────────────────────
# Keys are frozensets of two SPDX IDs so lookup is symmetric.
# Every pair appears only once; get_compatibility() normalizes order.

_COMPAT_TABLE: dict[frozenset, CompatResult] = {
    # CONFLICT pairs — ASF position 2007, FSF notes
    frozenset({"GPL-2.0-only",        "Apache-2.0"}):       "CONFLICT",
    frozenset({"GPL-3.0-only",        "Apache-2.0"}):       "CONFLICT",
    frozenset({"AGPL-3.0-or-later",   "MIT"}):              "CONFLICT",
    frozenset({"AGPL-3.0-or-later",   "Apache-2.0"}):       "CONFLICT",
    frozenset({"AGPL-3.0-or-later",   "BSD-2-Clause"}):     "CONFLICT",
    frozenset({"AGPL-3.0-or-later",   "BSD-3-Clause"}):     "CONFLICT",
    frozenset({"AGPL-3.0-or-later",   "ISC"}):              "CONFLICT",
    frozenset({"AGPL-3.0-or-later",   "LGPL-2.1-or-later"}):"CONFLICT",
    frozenset({"AGPL-3.0-or-later",   "MPL-2.0"}):          "CONFLICT",
    frozenset({"AGPL-3.0-only",       "MIT"}):              "CONFLICT",
    frozenset({"AGPL-3.0-only",       "Apache-2.0"}):       "CONFLICT",
    frozenset({"AGPL-3.0-only",       "BSD-2-Clause"}):     "CONFLICT",
    frozenset({"AGPL-3.0-only",       "BSD-3-Clause"}):     "CONFLICT",
    frozenset({"GPL-2.0-only",        "GPL-3.0-only"}):     "CONFLICT",   # version incompatibility
    frozenset({"GPL-2.0-or-later",    "Apache-2.0"}):       "CONFLICT",
    frozenset({"GPL-3.0-or-later",    "Apache-2.0"}):       "CONFLICT",
    frozenset({"EUPL-1.1",            "GPL-3.0-only"}):     "CONFLICT",
    frozenset({"EUPL-1.1",            "GPL-3.0-or-later"}): "CONFLICT",
    frozenset({"CDDL-1.0",            "GPL-2.0-only"}):     "CONFLICT",
    frozenset({"CDDL-1.0",            "GPL-3.0-only"}):     "CONFLICT",
    frozenset({"CPL-1.0",             "GPL-2.0-only"}):     "CONFLICT",

    # COMPATIBLE pairs
    frozenset({"MIT",                 "MIT"}):               "COMPATIBLE",
    frozenset({"MIT",                 "Apache-2.0"}):        "COMPATIBLE",
    frozenset({"MIT",                 "BSD-2-Clause"}):      "COMPATIBLE",
    frozenset({"MIT",                 "BSD-3-Clause"}):      "COMPATIBLE",
    frozenset({"MIT",                 "ISC"}):               "COMPATIBLE",
    frozenset({"MIT",                 "0BSD"}):              "COMPATIBLE",
    frozenset({"MIT",                 "Unlicense"}):         "COMPATIBLE",
    frozenset({"MIT",                 "CC0-1.0"}):           "COMPATIBLE",
    frozenset({"MIT",                 "WTFPL"}):             "COMPATIBLE",
    frozenset({"Apache-2.0",          "Apache-2.0"}):        "COMPATIBLE",
    frozenset({"Apache-2.0",          "BSD-2-Clause"}):      "COMPATIBLE",
    frozenset({"Apache-2.0",          "BSD-3-Clause"}):      "COMPATIBLE",
    frozenset({"Apache-2.0",          "ISC"}):               "COMPATIBLE",
    frozenset({"Apache-2.0",          "0BSD"}):              "COMPATIBLE",
    frozenset({"Apache-2.0",          "Unlicense"}):         "COMPATIBLE",
    frozenset({"Apache-2.0",          "CC0-1.0"}):           "COMPATIBLE",
    frozenset({"BSD-2-Clause",        "BSD-3-Clause"}):      "COMPATIBLE",
    frozenset({"BSD-2-Clause",        "BSD-2-Clause"}):      "COMPATIBLE",
    frozenset({"BSD-3-Clause",        "BSD-3-Clause"}):      "COMPATIBLE",
    frozenset({"BSD-2-Clause",        "ISC"}):               "COMPATIBLE",
    frozenset({"BSD-3-Clause",        "ISC"}):               "COMPATIBLE",
    frozenset({"ISC",                 "ISC"}):               "COMPATIBLE",
    frozenset({"MIT",                 "LGPL-2.1-only"}):     "COMPATIBLE",
    frozenset({"MIT",                 "LGPL-2.1-or-later"}): "COMPATIBLE",
    frozenset({"MIT",                 "LGPL-3.0-only"}):     "COMPATIBLE",
    frozenset({"MIT",                 "LGPL-3.0-or-later"}): "COMPATIBLE",
    frozenset({"Apache-2.0",          "LGPL-2.1-or-later"}): "COMPATIBLE",
    frozenset({"Apache-2.0",          "LGPL-3.0-or-later"}): "COMPATIBLE",
    frozenset({"LGPL-2.1-or-later",   "GPL-2.0-or-later"}): "COMPATIBLE",
    frozenset({"LGPL-2.1-only",       "GPL-2.0-only"}):     "COMPATIBLE",
    frozenset({"LGPL-3.0-or-later",   "GPL-3.0-or-later"}): "COMPATIBLE",
    frozenset({"MPL-2.0",             "Apache-2.0"}):        "COMPATIBLE",
    frozenset({"MPL-2.0",             "MIT"}):               "COMPATIBLE",
    frozenset({"MPL-2.0",             "BSD-2-Clause"}):      "COMPATIBLE",
    frozenset({"MPL-2.0",             "BSD-3-Clause"}):      "COMPATIBLE",
    frozenset({"GPL-2.0-or-later",    "GPL-3.0-or-later"}): "COMPATIBLE",
    frozenset({"GPL-3.0-only",        "GPL-3.0-or-later"}): "COMPATIBLE",
}

# ── Static licence metadata bundle (top-50 SPDX IDs) ──────────────────────────
# Used by fetch_licence_analysis as STATIC-FIRST source (no network call needed).
# Keys are SPDX IDs. Values: risk_level, osi_approved, fsf_libre, tldr snippet.

STATIC_LICENCES: dict[str, dict] = {
    "MIT": {
        "risk_level":    "PERMISSIVE",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   ["Include copyright notice and licence text in distributions"],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use"],
        "limitations":   ["No liability", "No warranty"],
        "plain_english": (
            "The MIT licence is one of the most permissive open source licences. "
            "You can use, copy, modify, and distribute this software freely, including "
            "in commercial products. The only requirement is to include the original "
            "copyright notice and licence text."
        ),
        "tldr": "Use freely with attribution. Commercial use allowed.",
    },
    "Apache-2.0": {
        "risk_level":    "PERMISSIVE",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   [
            "Include copyright notice and licence text",
            "State changes made to the source",
            "Include NOTICE file if present",
        ],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Patent use", "Private use"],
        "limitations":   ["No liability", "No warranty", "No trademark use"],
        "plain_english": (
            "Apache 2.0 is a permissive licence with an explicit patent grant. "
            "You can use it commercially, modify it, and distribute it. "
            "You must retain attribution, state changes, and include any NOTICE file."
        ),
        "tldr": "Use freely with attribution and NOTICE file. Includes patent grant.",
    },
    "GPL-2.0-only": {
        "risk_level":    "STRONG_COPYLEFT",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   [
            "Distribute source code of derivative works under GPL-2.0",
            "Include copyright notice and licence text",
            "Provide install instructions for user products",
        ],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use"],
        "limitations":   ["No liability", "No warranty", "Must share-alike ALL derivative works"],
        "plain_english": (
            "GPL-2.0 requires any derivative work you distribute to also be released "
            "under GPL-2.0 with full source code. This makes it incompatible with "
            "proprietary software distribution. Note: incompatible with Apache-2.0."
        ),
        "tldr": "All derivative works must be GPL-2.0 with source. Incompatible with Apache-2.0.",
    },
    "GPL-2.0-or-later": {
        "risk_level":    "STRONG_COPYLEFT",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   [
            "Distribute source code of derivative works under GPL-2.0 or later",
            "Include copyright notice and licence text",
        ],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use"],
        "limitations":   ["No liability", "No warranty", "Must share-alike ALL derivative works"],
        "plain_english": (
            "GPL-2.0-or-later allows you to choose GPL-2.0 or any later version (e.g., GPL-3.0). "
            "Any derivative work you distribute must include full source under the same licence."
        ),
        "tldr": "Share-alike required for all derivative works. Choose GPL-2.0 or later version.",
    },
    "GPL-3.0-only": {
        "risk_level":    "STRONG_COPYLEFT",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   [
            "Distribute source code of derivative works under GPL-3.0",
            "Include copyright notice and licence text",
            "Anti-tivoization: allow user modification on devices",
        ],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Patent use", "Private use"],
        "limitations":   ["No liability", "No warranty", "Must share-alike ALL derivative works"],
        "plain_english": (
            "GPL-3.0 requires any distributed derivative work to be released under GPL-3.0 "
            "with full source code. It adds anti-tivoization and patent retaliation clauses "
            "compared to GPL-2.0. Incompatible with Apache-2.0 (ASF position 2007)."
        ),
        "tldr": "All derivative works must be GPL-3.0 with source. Incompatible with Apache-2.0.",
    },
    "GPL-3.0-or-later": {
        "risk_level":    "STRONG_COPYLEFT",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   [
            "Distribute source code of derivative works under GPL-3.0 or later",
            "Include copyright notice and licence text",
        ],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Patent use", "Private use"],
        "limitations":   ["No liability", "No warranty", "Must share-alike ALL derivative works"],
        "plain_english": (
            "GPL-3.0-or-later allows choosing GPL-3.0 or any later version. "
            "Any derivative work you distribute must include full source under the same licence."
        ),
        "tldr": "Share-alike required for all derivative works under GPL-3.0 or later.",
    },
    "LGPL-2.1-only": {
        "risk_level":    "COPYLEFT",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   [
            "Modifications to LGPL-licensed files must be released under LGPL",
            "Allow reverse engineering for debugging",
            "Include copyright notice and licence text",
        ],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use", "Link from proprietary code"],
        "limitations":   ["No liability", "No warranty"],
        "plain_english": (
            "LGPL-2.1 is a weak copyleft licence. You can link against it from proprietary "
            "software, but modifications to the LGPL-licensed files themselves must be "
            "released under LGPL."
        ),
        "tldr": "Link freely from proprietary code. Modifications to LGPL files must be shared.",
    },
    "LGPL-2.1-or-later": {
        "risk_level":    "COPYLEFT",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   [
            "Modifications to LGPL-licensed files must be released under LGPL",
            "Allow reverse engineering for debugging",
        ],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use", "Link from proprietary code"],
        "limitations":   ["No liability", "No warranty"],
        "plain_english": (
            "LGPL-2.1-or-later is a weak copyleft licence. Linking from proprietary software "
            "is permitted. Modifications to the LGPL files themselves must be released under LGPL."
        ),
        "tldr": "Link freely from proprietary code. Modifications to LGPL files must be shared.",
    },
    "LGPL-3.0-only": {
        "risk_level":    "COPYLEFT",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   [
            "Modifications to LGPL-licensed files must be released under LGPL-3.0",
            "Include installation information for user products",
        ],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use", "Link from proprietary code"],
        "limitations":   ["No liability", "No warranty"],
        "plain_english": (
            "LGPL-3.0 is built on GPL-3.0 with a linking exception. You can link against it "
            "from proprietary software, but modifications to the LGPL-licensed files must be "
            "released under LGPL-3.0."
        ),
        "tldr": "Link freely from proprietary code. Modifications to LGPL files must be shared.",
    },
    "LGPL-3.0-or-later": {
        "risk_level":    "COPYLEFT",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   ["Modifications to LGPL files must be released under LGPL-3.0 or later"],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use", "Link from proprietary code"],
        "limitations":   ["No liability", "No warranty"],
        "plain_english": (
            "LGPL-3.0-or-later allows linking from proprietary code. Modifications to the "
            "LGPL-licensed files themselves must be released under LGPL-3.0 or later."
        ),
        "tldr": "Link freely from proprietary code. Modifications to LGPL files must be shared.",
    },
    "AGPL-3.0-only": {
        "risk_level":    "INCOMPATIBLE",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   [
            "All derivative works AND network-accessible software must release source under AGPL-3.0",
            "Include copyright notice and licence text",
        ],
        "permissions":   ["Modification", "Distribution", "Patent use", "Private use"],
        "limitations":   ["No commercial use in proprietary SaaS", "No liability", "No warranty"],
        "plain_english": (
            "AGPL-3.0 extends GPL-3.0 with a network-use clause: if you run this software as "
            "a service (SaaS), you must release the full source under AGPL-3.0. "
            "INCOMPATIBLE for proprietary SaaS. "
            "Compatible with open source projects — see SPDX for details."
        ),
        "tldr": "INCOMPATIBLE for proprietary/commercial use. Open source SaaS: source must be released.",
    },
    "AGPL-3.0-or-later": {
        "risk_level":    "INCOMPATIBLE",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   [
            "All derivative works AND network-accessible software must release source under AGPL-3.0 or later",
            "Include copyright notice and licence text",
        ],
        "permissions":   ["Modification", "Distribution", "Patent use", "Private use"],
        "limitations":   ["No commercial use in proprietary SaaS", "No liability", "No warranty"],
        "plain_english": (
            "AGPL-3.0-or-later extends GPL-3.0 with a network-use clause. Running this software "
            "as a service requires releasing source code under AGPL. "
            "INCOMPATIBLE for proprietary SaaS. "
            "Compatible with open source projects — see SPDX for details."
        ),
        "tldr": "INCOMPATIBLE for proprietary/commercial use. Open source: source must be released.",
    },
    "MPL-2.0": {
        "risk_level":    "COPYLEFT",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   [
            "Modifications to MPL-licensed files must be released under MPL-2.0",
            "Include copyright notice",
        ],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Patent use", "Private use"],
        "limitations":   ["No liability", "No warranty", "No trademark use"],
        "plain_english": (
            "MPL-2.0 is a file-level copyleft licence. Modifications to MPL-licensed files "
            "must be released, but you can combine MPL-2.0 code with proprietary code in "
            "the same project as separate files."
        ),
        "tldr": "Modifications to MPL files must be shared. Combination with proprietary code allowed.",
    },
    "BSD-2-Clause": {
        "risk_level":    "PERMISSIVE",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   ["Include copyright notice in source and binary distributions"],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use"],
        "limitations":   ["No liability", "No warranty"],
        "plain_english": (
            "BSD-2-Clause is a highly permissive licence requiring only attribution in "
            "source and binary distributions. Commercial use is fully permitted."
        ),
        "tldr": "Use freely with attribution. Commercial use allowed.",
    },
    "BSD-3-Clause": {
        "risk_level":    "PERMISSIVE",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   [
            "Include copyright notice in source and binary distributions",
            "Do not use project name to endorse derived products without permission",
        ],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use"],
        "limitations":   ["No liability", "No warranty", "No endorsement without permission"],
        "plain_english": (
            "BSD-3-Clause adds a non-endorsement clause to BSD-2-Clause. "
            "You cannot use the project name to promote derived products without permission."
        ),
        "tldr": "Use freely with attribution. No endorsement clause. Commercial use allowed.",
    },
    "ISC": {
        "risk_level":    "PERMISSIVE",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   ["Include copyright notice and licence text"],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use"],
        "limitations":   ["No liability", "No warranty"],
        "plain_english": (
            "ISC is functionally equivalent to MIT/BSD-2-Clause. Very permissive, "
            "requires only copyright attribution."
        ),
        "tldr": "Use freely with attribution. Commercial use allowed.",
    },
    "0BSD": {
        "risk_level":    "PERMISSIVE",
        "osi_approved":  True,
        "fsf_libre":     False,
        "obligations":   [],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use"],
        "limitations":   ["No liability", "No warranty"],
        "plain_english": "0BSD is a public-domain-equivalent licence with no attribution required.",
        "tldr": "No restrictions. Use however you want.",
    },
    "Unlicense": {
        "risk_level":    "PERMISSIVE",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   [],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use"],
        "limitations":   ["No liability", "No warranty"],
        "plain_english": "The Unlicense dedicates software to the public domain. No restrictions apply.",
        "tldr": "Public domain. No restrictions.",
    },
    "CC0-1.0": {
        "risk_level":    "PERMISSIVE",
        "osi_approved":  False,
        "fsf_libre":     True,
        "obligations":   [],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use"],
        "limitations":   ["No liability", "No warranty"],
        "plain_english": "CC0-1.0 waives all copyright. Equivalent to public domain dedication.",
        "tldr": "Public domain waiver. No restrictions.",
    },
    "EUPL-1.1": {
        "risk_level":    "STRONG_COPYLEFT",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   [
            "Distribute source code of derivative works under EUPL-1.1 or compatible licence",
            "Include copyright notice",
        ],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use"],
        "limitations":   ["No liability", "No warranty"],
        "plain_english": (
            "EUPL-1.1 is a European copyleft licence. Derivative works must be distributed "
            "under EUPL-1.1 or a compatible licence. Incompatible with GPL-3.0-only."
        ),
        "tldr": "Copyleft. Derivative works under EUPL or compatible. Incompatible with GPL-3.0-only.",
    },
    "CDDL-1.0": {
        "risk_level":    "COPYLEFT",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   [
            "Modifications to CDDL-licensed files must be released under CDDL-1.0",
            "Include copyright notice",
        ],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use"],
        "limitations":   ["No liability", "No warranty", "Incompatible with GPL"],
        "plain_english": (
            "CDDL-1.0 is a file-level copyleft licence from Sun Microsystems. "
            "Modifications to CDDL files must be released under CDDL. Incompatible with GPL."
        ),
        "tldr": "File-level copyleft. Modifications must be shared. Incompatible with GPL.",
    },
    "CPL-1.0": {
        "risk_level":    "COPYLEFT",
        "osi_approved":  True,
        "fsf_libre":     True,
        "obligations":   [
            "Modifications must be released under CPL-1.0",
            "Include copyright notice",
        ],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use"],
        "limitations":   ["No liability", "No warranty", "Incompatible with GPL-2.0-only"],
        "plain_english": (
            "CPL-1.0 (Common Public Licence) is an IBM copyleft licence. "
            "Modifications must be shared. Incompatible with GPL-2.0-only."
        ),
        "tldr": "Copyleft. Modifications must be shared. Incompatible with GPL-2.0-only.",
    },
    "WTFPL": {
        "risk_level":    "PERMISSIVE",
        "osi_approved":  False,
        "fsf_libre":     True,
        "obligations":   [],
        "permissions":   ["Commercial use", "Modification", "Distribution", "Private use"],
        "limitations":   [],
        "plain_english": "WTFPL is a public-domain-equivalent joke licence. No restrictions apply.",
        "tldr": "Do What the F*** You Want. No restrictions.",
    },
}


def get_compatibility(spdx_a: str, spdx_b: str) -> CompatResult:
    """
    Return COMPATIBLE | CONFLICT | UNKNOWN for a pair of SPDX licence IDs.
    Symmetric: get_compatibility(A, B) == get_compatibility(B, A).
    """
    key = frozenset({spdx_a.strip(), spdx_b.strip()})
    return _COMPAT_TABLE.get(key, "UNKNOWN")
