"""
datanexus/tools/_circuit_breakers.py — Centralized pybreaker singleton instances.

ALL circuit breakers must be defined here and imported by callers.
Never define a new pybreaker.CircuitBreaker() in a tool file — two separate
instances on the same upstream do not share failure state, so the circuit
would never open during an outage.

Callers:
  _security_utils.py   → _nvd_breaker, _depsdev_breaker, _osv_breaker
  _maintainer_utils.py → _pypi_stats_breaker, _npm_stats_breaker
  security_sprint6.py  → _pypi_stats_breaker, _npm_stats_breaker
  nonprofit_sprint6.py → _propublica_breaker
  (Sprint 7 tools import from here too — never define new instances)
"""

import pybreaker

_propublica_breaker = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
_nvd_breaker        = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
_cisa_breaker       = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
_epss_breaker       = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
_spdx_breaker       = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
_pypi_stats_breaker = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
_npm_stats_breaker  = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
_depsdev_breaker    = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
_osv_breaker        = pybreaker.CircuitBreaker(fail_max=3, reset_timeout=30)
