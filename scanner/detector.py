"""
detector.py - Load regex patterns and scan text content for sensitive data.
"""

import re
import os
import logging
from pathlib import Path

import yaml

logger = logging.getLogger("s3spider")

# Severity sort order for display
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_COLORS = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "dim white",
}


class Pattern:
    """A single detection pattern."""

    def __init__(self, name: str, regex: str, severity: str):
        self.name = name
        self.severity = severity.lower()
        try:
            self.compiled = re.compile(regex, re.MULTILINE | re.IGNORECASE)
        except re.error as e:
            logger.warning(f"Invalid regex for pattern '{name}': {e}")
            self.compiled = None

    def search(self, text: str):
        """Return list of match objects found in text."""
        if self.compiled is None:
            return []
        return list(self.compiled.finditer(text))


class Detector:
    """Loads patterns from YAML and scans text content."""

    def __init__(self, patterns_file: str | None = None):
        if patterns_file is None:
            # Default to bundled patterns file
            patterns_file = os.path.join(
                Path(__file__).parent.parent, "patterns", "default.yaml"
            )
        self.patterns: list[Pattern] = []
        self._load(patterns_file)

    def _load(self, path: str):
        """Load patterns from a YAML file."""
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f)
            for entry in data.get("patterns", []):
                p = Pattern(
                    name=entry.get("name", "Unknown"),
                    regex=entry.get("regex", ""),
                    severity=entry.get("severity", "medium"),
                )
                self.patterns.append(p)
            logger.debug(f"Loaded {len(self.patterns)} patterns from {path}")
        except FileNotFoundError:
            logger.error(f"Patterns file not found: {path}")
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse patterns YAML: {e}")

    def add_patterns_from_file(self, path: str):
        """Merge additional patterns from another YAML file."""
        self._load(path)

    def scan(self, text: str) -> list[dict]:
        """
        Scan text for all patterns.

        Returns a list of finding dicts:
        {
            pattern_name: str,
            severity: str,
            line_number: int,
            line: str,        # full line containing the match
            match: str,       # the matched substring
        }
        """
        if not text:
            return []

        findings = []
        lines = text.splitlines()

        # Build a line-start offset map for fast line lookup
        offsets = []
        pos = 0
        for line in lines:
            offsets.append(pos)
            pos += len(line) + 1  # +1 for newline

        for pattern in self.patterns:
            for m in pattern.search(text):
                line_num = _offset_to_line(m.start(), offsets)
                full_line = lines[line_num] if line_num < len(lines) else ""
                findings.append({
                    "pattern_name": pattern.name,
                    "severity": pattern.severity,
                    "line_number": line_num + 1,
                    "line": full_line.strip(),
                    "match": m.group(0),
                })

        # Deduplicate: same pattern + same line
        seen = set()
        unique = []
        for f in findings:
            key = (f["pattern_name"], f["line_number"], f["match"])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        # Sort by severity then line number
        unique.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 99), x["line_number"]))
        return unique


def _offset_to_line(offset: int, offsets: list[int]) -> int:
    """Binary search to find line index from character offset."""
    lo, hi = 0, len(offsets) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if offsets[mid] <= offset:
            lo = mid
        else:
            hi = mid - 1
    return lo
