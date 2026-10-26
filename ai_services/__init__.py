"""Isolated AI processing boundary for E-WITNESS.

Components in this package execute outside the synchronous request-response path
and operate strictly on sanitized or explicitly scoped inputs. Outputs produced
by AI services are advisory and never overwrite authoritative evidence records.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
