"""
datanexus/core/ip_classifier.py — IP reputation and grey-list classification.

Grey IPs are still served; they are excluded from dn-daily and dn-returning.
All prefix lists confirmed via dn-whois-batch May 26 2026.
"""

import logging

log = logging.getLogger("datanexus.core.ip_classifier")

# ── Bulletproof / datacenter bot ranges (excluded from analytics) ─────────────

GREY_IP_PREFIXES: list[str] = [
    # ASN-based hosting ranges confirmed grey (see DATANEXUS_CONTEXT_MAY24.md)
    "213.209.159.",   # AS208137 Feo Prest SRL
    "79.124.40.",     # AS50360  Tamatiya EOOD
    "130.12.180.",    # AS202412 Omegatech LTD
    "5.61.209.",      # AS206264 Amarutu Technology
    "45.148.10.",     # AS48090  TECHOFF SRV LIMITED
    "185.91.127.",    # AS49581  Ferdinand Zink
    "109.120.184.",   # AS210644 AEZA GROUP LLC
    "80.94.95.",      # AS204428 SS-Net
    "149.50.122.",    # AS201814 MEVSPACE
    # Added May 26 2026 via dn-whois-batch
    "176.65.139.",    # Storm Industries / PFCLOUD-NET NL — bulletproof host
    "93.174.93.",     # IP Volume Inc NL — bulletproof host, chronic abuse
    "2.59.22.",       # Black HOST Ltd AT — bulletproof host
    "165.227.",       # DigitalOcean — datacenter bot range
    "64.226.",        # DigitalOcean — datacenter bot range
]

# ── Internet-wide scanners (is_grey=True but logged at INFO, not silently) ────

KNOWN_SCANNERS: list[str] = [
    "66.132.",        # Censys, Inc. — internet-wide security scanner
    "66.249.",        # Googlebot
]

# ── Confirmed organic / trusted infrastructure ────────────────────────────────

KNOWN_LEGIT: list[str] = [
    "173.66.27.4",    # Verizon Business / Laurel MD — security auditor
    "73.241.93.191",  # US organic — MIT EIN lookup
    "160.79.106.35",  # Google LLC / Anthropic Claude.ai infra
    "160.79.106.36",
    "160.79.106.37",
    "160.79.106.38",
    "107.20.6.60",    # Amazon EC2 us-east-1 — ListTools-only aggregator
]

# ── Watching — not grey, not fully trusted; excluded from NO analytics ─────────

WATCH_LIST: list[str] = [
    "77.83.39.",      # Lanedo.net NL — legitimate OSS consultancy, watching
                      # (prev. misidentified as KPROHOST LLC in May 24 context)
    "152.233.",       # RIPE NCC — measurement network, not a real user
]


def classify_ip(ip: str) -> dict:
    """
    Classify a client IP against known lists.

    Returns:
        {
            "is_grey":    bool,   # exclude from dn-daily / dn-returning
            "list_match": str,    # "grey_prefix" | "scanner" | "legit" |
                                  # "watch" | "unknown"
        }

    Precedence (highest → lowest):
        1. KNOWN_LEGIT exact match  → is_grey=False
        2. WATCH_LIST prefix        → is_grey=False
        3. KNOWN_SCANNERS prefix    → is_grey=True  (INFO log)
        4. GREY_IP_PREFIXES prefix  → is_grey=True  (silent)
        5. No match                 → is_grey=False
    """
    # 1. Exact KNOWN_LEGIT match
    if ip in KNOWN_LEGIT:
        return {"is_grey": False, "list_match": "legit"}

    # 2. WATCH_LIST prefix — do not grey
    for prefix in WATCH_LIST:
        if ip.startswith(prefix):
            return {"is_grey": False, "list_match": "watch"}

    # 3. Known scanners — grey but visible in logs
    for prefix in KNOWN_SCANNERS:
        if ip.startswith(prefix):
            log.info("Known scanner %s — excluded from metrics", ip)
            return {"is_grey": True, "list_match": "scanner"}

    # 4. Grey hosting / bulletproof prefixes
    for prefix in GREY_IP_PREFIXES:
        if ip.startswith(prefix):
            return {"is_grey": True, "list_match": "grey_prefix"}

    return {"is_grey": False, "list_match": "unknown"}
