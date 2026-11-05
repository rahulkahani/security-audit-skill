#!/usr/bin/env python3
"""Validate already-sanitized audit metadata and render private local reports.

No scanning, network access, subprocesses, or automatic remediation.
"""
import argparse
import csv
import datetime as dt
import html
import io
import json
import os
from pathlib import Path
import re
import sys

CATEGORIES = ("accounts", "permissions", "keys", "ai-connectors", "dependencies", "app-launch")
FIELDS = ("id", "category", "item", "evidence", "observed_at", "state", "confidence",
          "severity", "priority", "impact", "action", "action_readiness", "decision", "retest")
SECRET = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9]{16,}|"
    r"github_pat_[A-Za-z0-9_]{16,}|sk-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)|"
    r"\b(?:password|secret|token|api[_-]?key|authorization)\s*[:=]\s*\S+|"
    r"https?://[^\s/]+@|https?://\S+[?#]\S+", re.I)


class InvalidReport(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise InvalidReport(message)


def exact_keys(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys), "Invalid or unexpected fields; use the documented schema.")


def safe_text(value):
    require(isinstance(value, str) and 0 < len(value) <= 2000, "Text must contain 1–2000 characters.")
    require(not any(ord(c) < 32 and c not in "\n\t" for c in value), "Control characters are not allowed.")
    require(not SECRET.search(value), "Potential sensitive content rejected; sanitize input locally. No value was printed.")
    return value


def date(value):
    safe_text(value)
    try:
        parsed = dt.date.fromisoformat(value)
    except ValueError:
        raise InvalidReport("Use ISO calendar dates YYYY-MM-DD.") from None
    require(parsed.isoformat() == value, "Use ISO calendar dates YYYY-MM-DD.")
    return parsed


def validate(data):
    exact_keys(data, ("schema_version", "as_of", "scope", "summary", "next_step", "coverage", "findings", "limitations"))
    require(type(data["schema_version"]) is int and data["schema_version"] == 1, "Unsupported schema version.")
    as_of = date(data["as_of"])
    safe_text(data["scope"])
    safe_text(data["summary"])
    safe_text(data["next_step"])
    require(isinstance(data["coverage"], list) and len(data["coverage"]) == len(CATEGORIES), "Provide coverage for every category.")
    seen = set()
    for row in data["coverage"]:
        exact_keys(row, ("category", "status", "detail"))
        for value in row.values():
            safe_text(value)
        require(row["category"] in CATEGORIES and row["category"] not in seen, "Coverage categories must be unique and recognized.")
        seen.add(row["category"])
        require(row["status"] in ("checked", "partial", "blocked", "not-requested", "not-applicable"), "Invalid coverage status.")
    require(isinstance(data["findings"], list) and len(data["findings"]) <= 1000, "Findings must be a list with at most 1000 entries.")
    ids = set()
    coverage = {r["category"]: r["status"] for r in data["coverage"]}
    for row in data["findings"]:
        exact_keys(row, FIELDS)
        for value in row.values():
            safe_text(value)
        require(bool(re.fullmatch(r"F-[0-9]{3,6}", row["id"])) and row["id"] not in ids, "Finding IDs must be unique F-001 style identifiers.")
        ids.add(row["id"])
        require(row["category"] in CATEGORIES, "Invalid finding category.")
        require(coverage[row["category"]] in ("checked", "partial"), "Findings require checked or partial category coverage.")
        require(date(row["observed_at"]) <= as_of, "Observation cannot be after report date.")
        for field, choices in {
            "state": ("confirmed", "candidate", "unknown"),
            "confidence": ("high", "medium", "low"),
            "severity": ("critical", "high", "medium", "low", "informational", "unknown"),
            "priority": ("now", "this-week", "later", "investigate"),
            "action_readiness": ("review-now", "needs-evidence"),
            "decision": ("pending", "keep", "review-change", "accepted-risk", "resolved"),
        }.items():
            require(row[field] in choices, "Invalid finding classification.")
    require(isinstance(data["limitations"], list) and 1 <= len(data["limitations"]) <= 100, "Provide at least one limitation.")
    for value in data["limitations"]:
        safe_text(value)
    return data


def markdown(value):
    value = re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", value)
    value = html.escape(value, quote=False)
    return value.replace("\r", " ").replace("\n", " ").replace("\t", " ")


def csv_cell(value):
    # Quoting alone does not stop formulas in spreadsheet applications.
    if value[:1] in ("\t", "\r", "\n") or value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def render(data):
    validate(data)
    priority = {p: i for i, p in enumerate(("now", "this-week", "investigate", "later"))}
    rows = sorted(data["findings"], key=lambda r: (priority[r["priority"]], r["id"]))
    lines = ["# Security audit", "", f"As of: {data['as_of']}", "", markdown(data["scope"]), "",
             "This is a review of supplied sanitized evidence, not a security certification.", "",
             f"Findings: {len(rows)}; confirmed conditions: {sum(r['state'] == 'confirmed' for r in rows)}; "
             f"candidate findings: {sum(r['state'] == 'candidate' for r in rows)}; unknown-state findings: {sum(r['state'] == 'unknown' for r in rows)}.",
             "Confirmed conditions can still have unknown attributes. These counts do not measure completeness.",
             "", markdown(data["summary"]),
             "", "## Coverage", "", "| Area | Status | Evidence / gap |", "| --- | --- | --- |"]
    for row in data["coverage"]:
        lines.append("| " + " | ".join(markdown(row[k]) for k in ("category", "status", "detail")) + " |")
    lines += ["", "## Findings", ""]
    if not rows:
        lines += ["No findings in the reviewed evidence. This does not establish safety or completeness.", ""]
    for row in rows:
        lines += [f"### {row['id']}: {markdown(row['item'])}", ""]
        for key in FIELDS[1:]:
            if key != "item":
                lines.append(f"- **{key.replace('_', ' ').title()}:** {markdown(row[key])}")
        lines.append("")
    lines += ["## Owner checklist", "", "Review actions only; no account, credential or configuration changes were performed by this formatter.", ""]
    for readiness, heading in (("review-now", "Decisions available now"), ("needs-evidence", "Verification requiring more evidence")):
        lines += [f"### {heading}", ""]
        group = [row for row in rows if row["action_readiness"] == readiness]
        for row in group:
            lines.append(f"- [ ] {row['id']} ({row['priority']}): {markdown(row['action'])} — decision: {row['decision']}")
        if not group:
            lines.append("None identified in this reviewed evidence.")
        lines.append("")
    lines += ["", "## Limitations", ""]
    lines += ["- " + markdown(x) for x in data["limitations"]]
    lines += ["", "Keep this report private. Review and sanitize again before sharing or committing it.", "", "## Next step", "", markdown(data["next_step"]), ""]
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(FIELDS)
    writer.writerows([[csv_cell(row[k]) for k in FIELDS] for row in rows])
    return "\n".join(lines), stream.getvalue()


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON fields are not allowed.")
        result[key] = value
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        require(args.input.is_file() and not args.input.is_symlink(), "Input must be a regular, non-symlink JSON file.")
        with args.input.open("rb") as handle:
            raw = handle.read(2_000_001)
        require(len(raw) <= 2_000_000, "Input exceeds 2 MB limit.")
        data = json.loads(raw, object_pairs_hook=reject_duplicates)
        report, sheet = render(data)
        # Resolve an existing parent first; /tmp is a standard symlink on macOS.
        require(args.output_dir.name not in ("", ".", ".."), "Choose a new output directory name.")
        destination = args.output_dir.parent.resolve(strict=True) / args.output_dir.name
        destination.mkdir(mode=0o700, parents=False, exist_ok=False)
        for name, content in (("report.md", report), ("findings.csv", sheet)):
            with os.fdopen(os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8", newline="") as handle:
                handle.write(content)
        print("Created report.md and findings.csv in the requested private output directory.")
        return 0
    except (InvalidReport, OSError, ValueError, RecursionError):
        # Parser/OS error messages can echo input content or sensitive paths.
        print("Report not completed. Check sanitized input/schema and use a new directory under an existing trusted parent. No input values were printed.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
