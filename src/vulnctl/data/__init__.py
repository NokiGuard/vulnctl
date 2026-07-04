"""Bundled offline snapshots (EPSS CSV, KEV JSON), shipped inside the wheel.

Each snapshot is a gzipped capture of the real feed, dated in its header /
metadata, giving ``--offline`` a cold-start baseline (FRAMEWORK.md §4).
"""
