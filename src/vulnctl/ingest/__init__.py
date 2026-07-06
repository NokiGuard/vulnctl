"""Ingest layer: one parser module per input type, all returning ``list[Finding]``."""


class IngestError(Exception):
    """Malformed input file: a hard error with an actionable message (CLAUDE.md rule 3)."""
