"""Bundled offline snapshots (EPSS CSV, KEV JSON, exploit index), in the wheel.

Each snapshot is a gzipped capture of the real feed, dated in its header /
metadata, giving ``--offline`` a cold-start baseline (FRAMEWORK.md §4).

``exploit_index.json.gz`` is a normalized CVE→exploit-presence map built from
Exploit-DB, Metasploit, and nuclei by ``scripts/build_exploit_index.py``; the
exploit adapter reads it directly (there is no per-CVE live API for v0.1).
"""
