#!/usr/bin/env python3
"""Apply exact-source advisory dispositions to the reviewed OS configurations."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = "scripts/security/dependency-review.json"
HOST = "x86_64-unknown-linux-gnu"
SCOPES = {
    "workspace": ("Cargo.toml", HOST),
    "guest": ("zksync_os/Cargo.toml", "riscv32im-risc0-zkvm-elf"),
}
DATABASE_URL = "https://github.com/RustSec/advisory-db"
DENY_VERSION = "0.20.2"


def source_fingerprint(root):
    names = set(filter(None, run([
        "git", "ls-files", "--cached", "--others", "--exclude-standard", "-z",
    ], root).split("\0")))
    result = hashlib.sha256()
    for name in sorted(names):
        if (name == POLICY_PATH or Path(name).suffix.lower() in {".md", ".pdf"}
                or "__pycache__" in Path(name).parts):
            continue
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"source input is not a regular file: {name}")
        mode = "executable" if path.stat().st_mode & stat.S_IXUSR else "regular"
        result.update(name.encode() + b"\0" + mode.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    return result.hexdigest()


def validate_host(environ, system, machine):
    if system != "Linux" or machine not in {"x86_64", "AMD64"}:
        raise ValueError(f"reviewed analysis host is {HOST}")
    for name in environ:
        if (name in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET", "RUSTC",
                     "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTFLAGS"}
                or name.startswith("CARGO_PROFILE_")
                or re.fullmatch(r"CARGO_TARGET_.*_(?:RUSTFLAGS|LINKER)", name)):
            raise ValueError(f"unreviewed compiler override: {name}")


def validate_features(metadata):
    packages = {p["id"]: p for p in metadata["packages"]}
    for node in metadata["resolve"]["nodes"]:
        name = packages[node["id"]]["name"]
        forbidden = {
            "aws-sigv4": {"sigv4a"},
            "der": {"bigint"},
            "crypto-bigint": {"alloc"},
        }.get(name, set())
        if forbidden.intersection(node["features"]):
            raise ValueError(f"unreviewed secret arithmetic features for {name}")


def fingerprints(root, scope, metadata):
    manifest, _ = SCOPES[scope]
    lock_path = Path(manifest).with_name("Cargo.lock")
    return {
        "lock_sha256": digest((root / lock_path).read_bytes()),
        "source_sha256": source_fingerprint(root),
        "graph_sha256": graph_fingerprint(metadata, root),
    }


def validate_context(root, policy, scope, metadata, compiler):
    if policy["schema"] != 1 or policy["host"] != HOST:
        raise ValueError("unsupported advisory review scope")
    review = policy["scopes"][scope]
    manifest, target = SCOPES[scope]
    if review["target"] != target or review["manifest"] != manifest:
        raise ValueError("target or manifest differs from the reviewed scope")
    if f"commit-hash: {policy['rustc_commit']}\n" not in compiler:
        raise ValueError("compiler differs from the reviewed toolchain")
    validate_packages(tomllib.loads((root / Path(manifest).with_name("Cargo.lock")).read_text()), review)
    validate_features(metadata)
    for key, value in fingerprints(root, scope, metadata).items():
        if value != review[key]:
            raise ValueError(f"{scope} {key}: review is stale (actual {value})")
    return review


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(command, root=ROOT):
    result = subprocess.run(command, cwd=root, text=True, capture_output=True)
    if result.returncode:
        raise ValueError(f"{shlex.join(map(str, command))} failed:\n{result.stderr}")
    return result.stdout


def graph_fingerprint(metadata, root):
    packages = {}
    for package in metadata["packages"]:
        source = package["source"]
        if source is None:
            try:
                relative = Path(package["manifest_path"]).relative_to(root).as_posix()
            except ValueError as error:
                raise ValueError("unreviewed dependency outside the workspace") from error
            source = "workspace:" + relative
        packages[package["id"]] = (package["name"], package["version"], source)
    nodes = []
    for node in metadata["resolve"]["nodes"]:
        dependencies = sorted(
            (dep["name"], packages[dep["pkg"]],
             sorted((kind.get("kind") or "normal", kind.get("target") or "")
                    for kind in dep["dep_kinds"]))
            for dep in node["deps"]
        )
        nodes.append((packages[node["id"]], sorted(node["features"]), dependencies))
    return digest(json.dumps(sorted(nodes), separators=(",", ":")).encode())


def validate_packages(lock, policy):
    for name, expected in policy["packages"].items():
        matches = [p for p in lock["package"] if p["name"] == name]
        if len(matches) != 1 or any(matches[0].get(k) != expected[k]
                                    for k in ("version", "source", "checksum")):
            raise ValueError(f"{name}: unreviewed package identity")


def validate_advisories(database, policy):
    for advisory_id, review in policy["advisories"].items():
        path = database / "crates" / review["package"] / f"{advisory_id}.md"
        try:
            actual = digest(path.read_bytes())
        except OSError as error:
            raise ValueError(f"{advisory_id}: reviewed advisory is missing") from error
        if not review["rationale"] or actual != review["sha256"]:
            raise ValueError(f"{advisory_id}: advisory contents changed; re-review required")


def _filter_report(report, policy, scanner, legacy_ignores):
    settings = report["settings"]
    if not isinstance(settings["ignore"], list) or not all(isinstance(value, str) for value in settings["ignore"]):
        raise ValueError("malformed scanner settings")
    ignored = set(settings["ignore"])
    if ignored - legacy_ignores or ignored.intersection(policy["advisories"]):
        raise ValueError("unexpected global advisory ignore")
    vulnerabilities = report["vulnerabilities"]
    if scanner == "audit":
        findings = vulnerabilities["list"]
        if (not isinstance(findings, list)
                or type(vulnerabilities["found"]) is not bool
                or type(vulnerabilities["count"]) is not int
                or vulnerabilities["count"] != len(findings)
                or vulnerabilities["found"] != bool(findings)):
            raise ValueError("inconsistent audit report")
        findings = list(findings)
    elif scanner == "deny" and isinstance(vulnerabilities, list):
        findings = list(vulnerabilities)
    else:
        raise ValueError("unexpected scanner report")
    if not isinstance(findings, list) or not isinstance(report["warnings"], dict):
        raise ValueError("malformed scanner findings")
    for kind, warnings in report["warnings"].items():
        if (kind not in {"unsound", "unmaintained", "notice", "yanked"}
                or not isinstance(warnings, list)
                or not all(isinstance(warning, dict) for warning in warnings)):
            raise ValueError(f"unknown warning category: {kind}")
        if kind == "unsound":
            findings.extend(warnings)
    accepted, remaining = [], []
    for finding in findings:
        advisory = finding["advisory"]
        package = finding["package"]
        advisory_id = advisory["id"]
        if advisory_id in ignored:
            continue
        review = policy["advisories"].get(advisory_id)
        expected = policy["packages"].get(package["name"])
        if review is not None:
            if (review["package"] != package["name"] or expected is None
                    or advisory["package"] != package["name"]):
                raise ValueError(f"{advisory_id}: unexpected package")
            if any(package.get(k) != expected[k] for k in ("version", "source")):
                raise ValueError(f"{advisory_id}: unexpected package identity")
            checksum = package.get("checksum")
            if checksum != expected["checksum"] and not (scanner == "deny" and checksum is None):
                raise ValueError(f"{advisory_id}: unexpected package checksum")
            accepted.append(finding)
        else:
            remaining.append(finding)
    return accepted, remaining


def filter_report(report, policy, scanner, legacy_ignores):
    try:
        return _filter_report(report, policy, scanner, legacy_ignores)
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("malformed scanner report") from error


def deny_diagnostics(stderr):
    for line in stderr.splitlines():
        item = json.loads(line)
        fields = item["fields"]
        if (fields.get("level") == "ERROR"
                or (fields.get("severity") == "error"
                    and fields.get("code") not in {"vulnerability", "unsound"})):
            raise ValueError(f"cargo-deny operational error: {fields}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scope", choices=SCOPES)
    parser.add_argument("--fingerprints", action="store_true",
                        help="print evidence for review; never update policy or accept findings")
    args = parser.parse_args()
    manifest, target = SCOPES[args.scope]
    metadata = json.loads(run([
        "cargo", "metadata", "--locked", "--all-features", "--manifest-path", manifest,
        "--filter-platform", target, "--format-version", "1",
    ]))
    if args.fingerprints:
        print(json.dumps(fingerprints(ROOT, args.scope, metadata), indent=2))
        return
    validate_host(os.environ, platform.system(), platform.machine())
    policy = json.loads((ROOT / POLICY_PATH).read_text())
    compiler = run(["rustc", "--version", "--verbose"])
    review = validate_context(ROOT, policy, args.scope, metadata, compiler)
    base = (ROOT / "deny.toml").read_text()
    if tomllib.loads(base)["advisories"]["ignore"]:
        raise ValueError("global advisory ignores are not permitted")
    if not re.search(rf"\b{re.escape(DENY_VERSION)}\s*$", run(["cargo", "deny", "--version"])):
        raise ValueError("cargo-deny version differs from the reviewed scanner")
    output = ROOT / "target/dependency-review" / args.scope
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="os-dependency-review-") as temporary:
        temporary = Path(temporary)
        metadata_path = temporary / "metadata.json"
        metadata_path.write_text(json.dumps(metadata))
        config = temporary / "deny.toml"
        config.write_text(base.replace(
            "[advisories]\n", f'[advisories]\ndb-path = "{temporary / "databases"}"\n', 1,
        ))
        run(["cargo", "deny", "--config", str(config), "fetch", "db"])
        databases = list((temporary / "databases").glob("*/crates"))
        if len(databases) != 1:
            raise ValueError("expected one RustSec advisory database")
        database = databases[0].parent
        validate_advisories(database, review)
        revision = run(["git", "rev-parse", "HEAD"], database).strip()
        common = ["cargo", "deny", "--format", "json", "--metadata-path", str(metadata_path),
                  "--config", str(config), "--target", target, "--all-features", "--locked", "--offline"]
        # Source, license and ban errors remain independent of advisory triage.
        run(common + ["check", "bans", "licenses", "sources", "--allow", "unmaintained"])
        result = subprocess.run(common + [
            "check", "advisories", "--allow", "unmaintained", "--audit-compatible-output",
        ], cwd=ROOT, text=True, capture_output=True)
        (output / "raw.json").write_text(result.stdout)
        (output / "stderr.log").write_text(result.stderr)
        if result.returncode not in {0, 1}:
            raise ValueError(f"cargo-deny failed with status {result.returncode}: {result.stderr}")
        deny_diagnostics(result.stderr)
        accepted, remaining = filter_report(json.loads(result.stdout), review, "deny", set())
        if result.returncode and not (accepted or remaining):
            raise ValueError("scanner failed without a vulnerability or unsoundness finding")
        summary = {
            "scope": args.scope, "target": target, "advisory_db": revision,
            **fingerprints(ROOT, args.scope, metadata),
            "accepted": [{"id": f["advisory"]["id"], "package": f["package"]["name"],
                          "rationale": review["advisories"][f["advisory"]["id"]]["rationale"]}
                         for f in accepted],
            "remaining": remaining,
        }
        (output / "review.json").write_text(json.dumps(summary, indent=2) + "\n")
        if remaining:
            raise ValueError(f"{len(remaining)} unreviewed vulnerability or unsoundness finding(s)")
        validate_context(ROOT, policy, args.scope, metadata, compiler)
        validate_advisories(database, review)
        print(f"PASS {args.scope}: {len(accepted)} scoped dispositions; no unreviewed findings; RustSec {revision}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f"OS dependency review failed: {error}", file=sys.stderr)
        sys.exit(1)
