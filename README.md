# safe-rulesets

Pre-processed secret-detection ruleset derived from upstream [gitleaks](https://github.com/gitleaks/gitleaks).

A daily GitHub Action fetches the upstream [gitleaks.toml](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml),
translates Go RE2 regex syntax to ICU (compatible with most regex engines including `NSRegularExpression`,
Java/JS), drops rules that don't survive the translation, and commits the result to `latest.json` on `master`.

Downstream consumers fetch the ruleset directly from:

```
https://raw.githubusercontent.com/emanuel-braz/safe-rulesets/master/latest.json
```

## Files

- `latest.json` — the envelope. Versioned by truncated SHA-256 of the upstream TOML.
- `report.json` — which upstream rules were dropped during translation and why. Useful when investigating false negatives.
- `scripts/build-ruleset.py` — the converter. Runs in CI; can also be run locally with `python3 scripts/build-ruleset.py`.

## Envelope schema

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
      "allowlists": [{ "regexes": ["..."], "regexTarget": "secret|match|line", "stopwords": ["..."], "condition": "or|and" }],
      "requiredRules": [{ "ruleID": "...", "withinLines": 2, "withinColumns": null }]
    }
  ]
}
```

## Local run

```bash
python3 scripts/build-ruleset.py
```

Requires Python 3.11+ (uses stdlib `tomllib`).
