# safe-rulesets

Pre-processed catalogs and rulesets for client-side secret detection and
compromised-dependency alerting. Consumed by downstream applications via
plain HTTP GET (no auth, ETag-based caching).

Two artifacts are published from this repo:

| File | Purpose |
|---|---|
| `latest.json` | Secret-detection ruleset (regex + entropy + allowlists + keywords + composite-rule references). Translated from upstream TOML format to ICU-compatible regex so it runs on `NSRegularExpression`, Java, JS, etc. |
| `compromised-packages.json` | Minimalist catalog of compromised package releases across npm / PyPI / pub. Carries `(ecosystem, name, advisory id, severity, version ranges)` only; human-readable advisory text is fetched lazily by id when needed. |

Each artifact has a sibling report file (`report.json`, `compromised-packages-report.json`)
describing what was dropped during translation/filtering and why.

## Endpoints

```
https://raw.githubusercontent.com/emanuel-braz/safe-rulesets/master/latest.json
https://raw.githubusercontent.com/emanuel-braz/safe-rulesets/master/compromised-packages.json
```

Both responses send an `ETag` header — clients should send `If-None-Match` on
subsequent fetches so 304 short-circuits avoid re-downloading unchanged data.

## Update cadence

- Secret-detection ruleset: refreshed daily at 04:00 UTC, committed only if the
  upstream source changed.
- Compromised-packages catalog: refreshed daily at 04:30 UTC, same change-only
  commit policy.

Both syncs run as GitHub Actions in this repo and can be triggered manually
from the Actions tab (`Run workflow`).

## Schemas

### `latest.json` (secret-detection ruleset)

```json
{
  "version": "abc1234567890",
  "fetchedAt": "ISO-8601 timestamp",
  "rules": [
    {
      "id": "string",
      "name": "string",
      "category": "string",
      "regex": "ICU-compatible regex",
      "captureGroup": 0,
      "replacementTag": "STRING",
      "confidence": "high|medium|low",
      "entropy": 3.5,
      "keywords": ["..."],
      "allowlists": [
        { "regexes": ["..."], "regexTarget": "secret|match|line", "stopwords": ["..."], "condition": "or|and" }
      ],
      "requiredRules": [
        { "ruleID": "...", "withinLines": 2, "withinColumns": null }
      ]
    }
  ]
}
```

### `compromised-packages.json`

```json
{
  "v": "<sha-prefix>",
  "g": "ISO-8601 timestamp",
  "e": [
    {
      "k": "npm" | "PyPI" | "Pub",
      "n": "<package-name>",
      "i": "<advisory-id>",
      "s": "malicious|critical|high|medium|low|unknown",
      "r": [ { "i": "introduced", "f": "fixed", "la": "lastAffected" } ]
    }
  ]
}
```

Single-letter keys deliberately — keeps the catalog small as the corpus grows.

## Local run

```bash
python3 scripts/build-ruleset.py            # secret-detection ruleset
python3 scripts/build-compromised-packages.py  # compromised-packages catalog
```

Requires Python 3.11+ (uses stdlib `tomllib`).
