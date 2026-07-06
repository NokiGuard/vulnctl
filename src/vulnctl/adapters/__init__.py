"""Intel-source adapters. Importing this package registers every bundled adapter."""

from vulnctl.adapters import epss, ghsa, kev, nvd, osv

__all__ = ["epss", "ghsa", "kev", "nvd", "osv"]
