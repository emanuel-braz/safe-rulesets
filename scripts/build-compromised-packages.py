#!/usr/bin/env python3
"""
Build the compromised-packages catalog consumed by downstream apps.

Pulls from upstream vulnerability data, filters explicit malicious-release
classes across the ecosystems we care about (npm, PyPI, pub), and emits a
compact JSON envelope.

Output (repo root):
  - compromised-packages.json          minimalist envelope consumers fetch
  - compromised-packages-report.json   diagnostic: counts per ecosystem

Filter (strict — kept narrow on purpose to avoid blowing up size):
  - id in the dedicated "MAL-" namespace
  - upstream marker `malicious-packages-origins` present
  - allow-list of advisory ids known to describe a compromised release

Output schema (minimalist, single-letter keys):

    {
      "v": "<sha-prefix>",          # version hash
      "g": "<ISO datetime>",        # generatedAt
      "e": [
        {
          "k": "npm" | "PyPI" | "Pub",   # ecosystem (preserved casing)
          "n": "<package-name>",         # name
          "i": "<advisory-id>",          # advisory id
          "s": "malicious|critical|high|medium|low|unknown",   # severity
          "r": [                         # ranges (one or more)
            {"i": "x.y.z", "f": "a.b.c", "la": "x.y.w"}
          ]
        }
      ]
    }

  Range keys: `i` introduced, `f` fixed, `la` lastAffected. All optional inside
  a range; at least one event marker is always emitted.

  Human-readable advisory text (summary, details markdown, references,
  published, modified) is intentionally absent — downstream apps fetch it
  lazily by advisory id when they need to render an alert. Detection works
  offline using just (ecosystem, name, version, severity, ranges).
"""

from __future__ import annotations

import io
import json
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ECOSYSTEMS = [
    ("PyPI", "pypi"),
    ("npm",  "npm"),
    ("Pub",  "pub"),
]

BULK_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"

# Targeted advisory allow-list: known compromised releases of legitimate packages.
# Extend as new incidents are identified.
KNOWN_MALICIOUS_ADVISORIES: set[str] = {
    "GHSA-5mg7-485q-xm76",  # litellm 1.82.7-1.82.8 credential harvest
}


def fetch_zip(url: str) -> zipfile.ZipFile:
    with urllib.request.urlopen(url, timeout=60) as resp:
        data = resp.read()
    return zipfile.ZipFile(io.BytesIO(data))


def is_malicious(entry: dict) -> bool:
    """Strict filter. Accepts only:
      - the dedicated `MAL-*` namespace (explicit malicious package classification)
      - `database_specific.malicious-packages-origins` marker
      - explicit allow-list of advisory ids known to describe compromised releases
    """
    advisory_id = entry.get("id", "")
    if advisory_id.startswith("MAL-"):
        return True
    if entry.get("database_specific", {}).get("malicious-packages-origins"):
        return True
    if advisory_id in KNOWN_MALICIOUS_ADVISORIES:
        return True
    return False


def normalize_ranges(affected_block: dict) -> list[dict]:
    """Flatten upstream `ranges[].events[]` into the minimalist `{i, f, la}` shape.

    Source format: `events` is a list of {introduced, fixed, last_affected}
    in chronological order. We collapse to one event-per-range record.
    """
    out = []
    for r in affected_block.get("ranges") or []:
        introduced = None
        fixed = None
        last_affected = None
        for ev in r.get("events") or []:
            if "introduced" in ev:
                introduced = ev["introduced"]
            if "fixed" in ev:
                fixed = ev["fixed"]
            if "last_affected" in ev:
                last_affected = ev["last_affected"]
        if introduced or fixed or last_affected:
            entry = {}
            if introduced is not None: entry["i"] = introduced
            if fixed is not None: entry["f"] = fixed
            if last_affected is not None: entry["la"] = last_affected
            out.append(entry)
    # Fold an explicit `versions: ["1.82.7", "1.82.8"]` (no ranges section) into
    # discrete introduced/lastAffected = version entries.
    versions = affected_block.get("versions") or []
    if versions and not out:
        for v in versions:
            out.append({"i": v, "la": v})
    return out


def severity_for(entry: dict) -> str:
    """Default 'malicious' for filter-accepted entries. CVE severity from CVSS
    score string used as a tiebreaker for the rare case of a heuristic match."""
    if entry.get("id", "").startswith("MAL-"):
        return "malicious"
    if entry.get("database_specific", {}).get("malicious-packages-origins"):
        return "malicious"
    sevs = entry.get("severity") or []
    for s in sevs:
        score = s.get("score", "")
        if "9." in score or "10" in score:
            return "critical"
        if "7." in score or "8." in score:
            return "high"
    return "malicious"


def build_entries(eco_label: str, eco_lower: str, zf: zipfile.ZipFile) -> tuple[list[dict], int]:
    """Walk every JSON in the bulk zip, filter to malicious, emit minimalist rows."""
    out = []
    total = 0
    for member in zf.namelist():
        if not member.endswith(".json"):
            continue
        total += 1
        with zf.open(member) as fh:
            try:
                entry = json.load(fh)
            except Exception:
                continue
        if not is_malicious(entry):
            continue
        for aff in entry.get("affected") or []:
            pkg = aff.get("package") or {}
            if (pkg.get("ecosystem") or "").lower() != eco_label.lower():
                continue
            name = pkg.get("name")
            if not name:
                continue
            ranges = normalize_ranges(aff)
            if not ranges:
                # Wildcard fallback so a name-only match still has at least one row.
                ranges = [{"i": "0.0.0"}]
            row = {
                "k": eco_label,
                "n": name,
                "i": entry.get("id"),
                "s": severity_for(entry),
                "r": ranges,
            }
            out.append(row)
    return out, total


def main() -> int:
    all_entries: list[dict] = []
    report = {"fetchedAt": datetime.now(timezone.utc).isoformat(), "perEcosystem": {}}

    for eco_label, eco_lower in ECOSYSTEMS:
        url = BULK_URL.format(eco=eco_label)
        print(f"Fetching {url} ...")
        try:
            zf = fetch_zip(url)
        except Exception as e:
            print(f"  failed: {e}", file=sys.stderr)
            report["perEcosystem"][eco_label] = {"error": str(e)}
            continue
        entries, total = build_entries(eco_label, eco_lower, zf)
        all_entries.extend(entries)
        report["perEcosystem"][eco_label] = {"scanned": total, "kept": len(entries)}
        print(f"  {eco_label}: kept {len(entries)} of {total}")

    # Stable version key — SHA256/12 of sorted advisory ids.
    import hashlib
    ids = sorted({e["i"] for e in all_entries if e.get("i")})
    version = hashlib.sha256("\n".join(ids).encode("utf-8")).hexdigest()[:12]

    envelope = {
        "v": version,
        "g": report["fetchedAt"],
        "e": all_entries,
    }

    # `separators=(",", ":")` removes whitespace; we save ~15-20% bytes vs indented output.
    Path("compromised-packages.json").write_text(
        json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
    )
    report["totalEntries"] = len(all_entries)
    report["version"] = version
    Path("compromised-packages-report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False)
    )
    print(f"Wrote compromised-packages.json (version {version}, {len(all_entries)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
