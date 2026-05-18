#!/usr/bin/env python3
"""
Convert the upstream gitleaks TOML ruleset into a portable JSON envelope.

Rationale: keeping TOML parsing and the Go-RE2-to-ICU regex translation
off downstream consumers. Incompatible rules are dropped here and reported
to a side file; consumers only see pre-vetted patterns.

Inputs:
  - https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml

Outputs (in repo root):
  - latest.json   (the envelope consumers fetch)
  - report.json   (drop log: which rules were skipped and why)
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

GITLEAKS_TOML_URL = (
    "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
)

# Heuristic prefix → consumer category. Falls back to "userCustom".
CATEGORY_MAP = [
    (("aws", "azure", "gcp", "google", "digitalocean", "heroku", "fly", "scalingo", "openshift", "yandex", "alibaba", "tencent"), "cloud"),
    (("github", "gitlab", "bitbucket", "artifactory", "npm", "pypi", "rubygems", "clojars", "maven"), "scm"),
    (("databricks", "doppler", "dynatrace", "grafana", "newrelic", "sentry", "sumologic", "datadog", "splunk"), "observability"),
    (("slack", "discord", "telegram", "rocketchat", "mattermost"), "chat"),
    (("stripe", "square", "shippo", "lob", "flutterwave", "duffel", "easypost", "beamer", "paypal", "adyen"), "payments"),
    (("openai", "anthropic", "perplexity", "huggingface", "cohere", "replicate"), "ai"),
    (("linear", "notion", "postman", "frameio", "typeform", "readme", "octopus", "mapbox", "asana", "intercom"), "saas"),
    (("planetscale", "mongo", "supabase", "neon"), "database"),
    (("shopify", "woocommerce", "bigcommerce"), "ecommerce"),
    (("mailgun", "sendgrid", "sendinblue", "brevo", "postmark"), "email"),
    (("pulumi", "terraform", "prefect", "harness", "settlemint", "infracost", "circleci", "jenkins", "ansible"), "devops"),
    (("vault", "doppler", "akeyless"), "secretsVault"),
    (("auth0", "okta", "intra42", "clerk", "supabase", "firebase"), "auth"),
    (("1password", "bitwarden", "lastpass"), "passwordManager"),
    (("twilio", "plivo", "vonage", "nexmo"), "communication"),
    (("rsa", "private", "key", "pem", "pgp"), "cryptoKey"),
    (("generic", "api"), "kvHeuristic"),
]


def categorize(rule_id: str) -> str:
    lower = rule_id.lower()
    for prefixes, cat in CATEGORY_MAP:
        if any(lower.startswith(p) or p in lower for p in prefixes):
            return cat
    return "userCustom"


# Determines syntactic adjustments to go from Go RE2 to ICU (NSRegularExpression).
# Go RE2 is a strict subset of ICU minus a couple of syntax quirks — most rules
# work as-is. Known divergences we patch:
#   - Named groups: (?P<name>...) → (?<name>...)
#   - \h horizontal whitespace: not in ICU, replaced with [ \t]
RE2_TO_ICU_PATCHES = [
    (re.compile(r"\(\?P<"), "(?<"),
    (re.compile(r"\\h"), "[ \\t]"),
]


def translate_regex(pattern: str) -> str:
    out = pattern
    for matcher, replacement in RE2_TO_ICU_PATCHES:
        out = matcher.sub(replacement, out)
    return out


def icu_compiles(pattern: str) -> bool:
    """Best-effort sanity check: shell out to perl-like flavor via Python `re`.
    This is NOT identical to NSRegularExpression but catches obvious failures.
    The real validation happens at runtime in RemoteRulesetDecoder, which drops
    anything that doesn't compile in ICU."""
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def fetch_toml() -> str:
    with urllib.request.urlopen(GITLEAKS_TOML_URL, timeout=30) as resp:
        return resp.read().decode("utf-8")


def parse_toml(text: str):
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore
    return tomllib.loads(text)


def build_envelope(toml_data: dict, version: str) -> tuple[dict, dict]:
    rules_out = []
    dropped = []

    for rule in toml_data.get("rules", []):
        rid = rule.get("id")
        if not rid:
            continue
        raw_regex = rule.get("regex")
        if not raw_regex:
            dropped.append({"id": rid, "reason": "no regex"})
            continue
        translated = translate_regex(raw_regex)
        if not icu_compiles(translated):
            dropped.append({"id": rid, "reason": "regex did not compile after translation"})
            continue

        entry = {
            "id": rid,
            "name": rule.get("description", rid)[:80],
            "category": categorize(rid),
            "regex": translated,
            "captureGroup": rule.get("secretGroup", 0),
            "replacementTag": rid.upper().replace(".", "_").replace("-", "_"),
            "confidence": "high",
        }
        if "entropy" in rule:
            entry["entropy"] = float(rule["entropy"])
        keywords = rule.get("keywords")
        if keywords:
            entry["keywords"] = list(keywords)

        allowlists = []
        # gitleaks supports a single inline allowlist on `rule.allowlist` and/or
        # a list `rule.allowlists`. Normalize.
        if "allowlist" in rule:
            allowlists.append(rule["allowlist"])
        if "allowlists" in rule:
            allowlists.extend(rule["allowlists"])
        if allowlists:
            converted = []
            for al in allowlists:
                converted_al = {}
                if "regexes" in al:
                    converted_al["regexes"] = [translate_regex(r) for r in al["regexes"]]
                if "regexTarget" in al:
                    converted_al["regexTarget"] = al["regexTarget"]
                if "stopwords" in al:
                    converted_al["stopwords"] = list(al["stopwords"])
                if "condition" in al:
                    converted_al["condition"] = al["condition"]
                if converted_al:
                    converted.append(converted_al)
            if converted:
                entry["allowlists"] = converted

        if "required" in rule:
            entry["requiredRules"] = [
                {
                    "ruleID": r.get("id") or r.get("ruleID"),
                    "withinLines": r.get("withinLines") or r.get("within_lines"),
                    "withinColumns": r.get("withinColumns") or r.get("within_columns"),
                }
                for r in rule["required"]
                if r.get("id") or r.get("ruleID")
            ]

        rules_out.append(entry)

    envelope = {
        "version": version,
        "fetchedAt": datetime.now(timezone.utc).isoformat(),
        "rules": rules_out,
    }
    report = {
        "fetchedAt": envelope["fetchedAt"],
        "totalInput": len(toml_data.get("rules", [])),
        "totalOutput": len(rules_out),
        "dropped": dropped,
    }
    return envelope, report


def compute_version(toml_text: str) -> str:
    import hashlib
    h = hashlib.sha256(toml_text.encode("utf-8")).hexdigest()
    return h[:12]


def main() -> int:
    out_dir = Path(".")
    print("Fetching upstream gitleaks.toml...")
    toml_text = fetch_toml()
    version = compute_version(toml_text)
    print(f"Version (sha256/12): {version}")
    toml_data = parse_toml(toml_text)
    envelope, report = build_envelope(toml_data, version)
    print(f"Compiled {report['totalOutput']} of {report['totalInput']} rules; "
          f"dropped {len(report['dropped'])}")
    latest = out_dir / "latest.json"
    latest.write_text(json.dumps(envelope, indent=2, ensure_ascii=False))
    (out_dir / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"Wrote {latest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
