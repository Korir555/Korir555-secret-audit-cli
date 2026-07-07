#!/usr/bin/env python3
"""Defensive secret exposure scanner.

Scans repositories and local configuration paths for likely leaked secrets.
Findings are redacted by default so the tool can be used safely in terminals,
CI logs, and reports.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import math
import os
import re
import stat
import sys
from pathlib import Path
from typing import Iterable


DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".cache",
}

DEFAULT_INCLUDE_NAMES = {
    ".env",
    ".env.local",
    ".env.dev",
    ".env.development",
    ".env.prod",
    ".env.production",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "credentials",
    "config",
    "terraform.tfvars",
}

TEXT_EXTENSIONS = {
    ".bash",
    ".cfg",
    ".conf",
    ".config",
    ".env",
    ".ini",
    ".json",
    ".js",
    ".jsx",
    ".mjs",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".tf",
    ".tfvars",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
    ".zsh",
}

SECRET_PATTERNS = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_temp_access_key_id", re.compile(r"\bASIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_secret_key", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("private_key_header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]

KEY_VALUE_PATTERN = re.compile(
    r"(?i)\b("
    r"api[_-]?key|access[_-]?token|auth[_-]?token|bearer|client[_-]?secret|"
    r"db[_-]?password|password|passwd|private[_-]?key|secret|session[_-]?key|"
    r"token"
    r")\b\s*[:=]\s*['\"]?([^'\"\s#]{8,})"
)

HIGH_ENTROPY_PATTERN = re.compile(r"\b[A-Za-z0-9+/_-]{24,}\b")


@dataclasses.dataclass
class Finding:
    path: str
    line: int
    kind: str
    severity: str
    evidence: str
    fingerprint: str


def redact(value: str) -> str:
    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:16]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = {char: value.count(char) for char in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in frequencies.values())


def is_probably_text(path: Path, max_bytes: int) -> bool:
    if path.name in DEFAULT_INCLUDE_NAMES or path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    try:
        sample = path.read_bytes()[: min(2048, max_bytes)]
    except OSError:
        return False
    return b"\x00" not in sample


def iter_files(roots: Iterable[Path], max_bytes: int, follow_symlinks: bool) -> Iterable[Path]:
    for root in roots:
        if root.is_file():
            yield root
            continue
        for current, dirs, files in os.walk(root, followlinks=follow_symlinks):
            dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDES]
            for name in files:
                path = Path(current) / name
                try:
                    info = path.stat() if follow_symlinks else path.lstat()
                except OSError:
                    continue
                if stat.S_ISLNK(info.st_mode) and not follow_symlinks:
                    continue
                if info.st_size > max_bytes:
                    continue
                if is_probably_text(path, max_bytes):
                    yield path


def scan_text(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[int, str, str]] = set()
    for line_no, line in enumerate(text.splitlines(), start=1):
        line_value_fingerprints: set[str] = set()
        for kind, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                value = match.group(0)
                fp = fingerprint(value)
                line_value_fingerprints.add(fp)
                key = (line_no, kind, fp)
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        Finding(str(path), line_no, kind, "high", redact(value), fp)
                    )

        for match in KEY_VALUE_PATTERN.finditer(line):
            key_name, value = match.group(1), match.group(2)
            if looks_like_placeholder(value):
                continue
            fp = fingerprint(value)
            if fp in line_value_fingerprints:
                continue
            line_value_fingerprints.add(fp)
            key = (line_no, key_name.lower(), fp)
            if key not in seen:
                seen.add(key)
                severity = "high" if shannon_entropy(value) >= 3.2 or len(value) >= 20 else "medium"
                findings.append(
                    Finding(str(path), line_no, f"key_value:{key_name.lower()}", severity, redact(value), fp)
                )

        for match in HIGH_ENTROPY_PATTERN.finditer(line):
            value = match.group(0)
            fp = fingerprint(value)
            if fp in line_value_fingerprints or looks_like_placeholder(value) or not looks_like_secret_blob(value):
                continue
            key = (line_no, "high_entropy", fp)
            if key not in seen:
                seen.add(key)
                findings.append(
                    Finding(str(path), line_no, "high_entropy_blob", "medium", redact(value), fp)
                )
    return findings


def looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    placeholders = ("changeme", "example", "placeholder", "dummy", "xxxx", "your_", "test")
    return any(marker in lowered for marker in placeholders)


def looks_like_secret_blob(value: str) -> bool:
    if len(value) < 24 or shannon_entropy(value) < 3.8:
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) in {32, 40, 64, 128}:
        return True
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.b64decode(padded, validate=False)
        return len(decoded) >= 16
    except Exception:
        return True


def discover_sensitive_locations(home: Path) -> list[Path]:
    candidates = [
        home / ".aws" / "credentials",
        home / ".aws" / "config",
        home / ".azure",
        home / ".config" / "gcloud",
        home / ".docker" / "config.json",
        home / ".kube" / "config",
        home / ".netrc",
        home / ".npmrc",
        home / ".pypirc",
        home / ".ssh" / "config",
        home / ".password-store",
        home / ".config" / "gh",
        home / ".config" / "hub",
        home / "Library" / "Application Support" / "Code" / "User" / "settings.json",
    ]
    return [path for path in candidates if path.exists()]


def load_file(path: Path, max_bytes: int) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def summarize_password_stores(home: Path) -> list[dict[str, str]]:
    summaries: list[dict[str, str]] = []
    pass_store = home / ".password-store"
    if pass_store.exists():
        count = sum(1 for _ in pass_store.rglob("*.gpg")) if pass_store.is_dir() else 0
        summaries.append({"store": "pass", "path": str(pass_store), "entries": str(count)})
    bitwarden = home / ".config" / "Bitwarden CLI"
    if bitwarden.exists():
        summaries.append({"store": "bitwarden-cli", "path": str(bitwarden), "entries": "not_inspected"})
    one_password = home / ".config" / "op"
    if one_password.exists():
        summaries.append({"store": "1password-cli", "path": str(one_password), "entries": "not_inspected"})
    return summaries


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Find likely leaked secrets in repositories and local config files with redacted output."
    )
    parser.add_argument("paths", nargs="*", default=["."], help="Files or directories to scan.")
    parser.add_argument("--include-home-configs", action="store_true", help="Also scan common cloud and tool config paths.")
    parser.add_argument("--password-store-summary", action="store_true", help="Report password store locations without reading secrets.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    parser.add_argument("--max-bytes", type=int, default=1_000_000, help="Skip files larger than this size.")
    parser.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks while walking directories.")
    parser.add_argument("--fail-on-findings", action="store_true", help="Exit with code 2 when findings are present.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    roots = [Path(path).expanduser().resolve() for path in args.paths]
    if args.include_home_configs:
        roots.extend(discover_sensitive_locations(Path.home()))

    findings: list[Finding] = []
    scanned = 0
    for path in iter_files(roots, args.max_bytes, args.follow_symlinks):
        text = load_file(path, args.max_bytes)
        if text is None:
            continue
        scanned += 1
        findings.extend(scan_text(path, text))

    password_stores = summarize_password_stores(Path.home()) if args.password_store_summary else []

    if args.json:
        print(
            json.dumps(
                {
                    "scanned_files": scanned,
                    "finding_count": len(findings),
                    "findings": [dataclasses.asdict(finding) for finding in findings],
                    "password_stores": password_stores,
                },
                indent=2,
            )
        )
    else:
        print(f"Scanned files: {scanned}")
        print(f"Findings: {len(findings)}")
        for finding in findings:
            print(
                f"{finding.severity.upper():6} {finding.path}:{finding.line} "
                f"{finding.kind} evidence={finding.evidence} fp={finding.fingerprint}"
            )
        for store in password_stores:
            print(f"INFO   password_store {store['store']} path={store['path']} entries={store['entries']}")

    return 2 if findings and args.fail_on_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
