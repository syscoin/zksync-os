import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / "check-dependency-advisories.py"
spec = importlib.util.spec_from_file_location("dependency_review", MODULE)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
PACKAGE = {"name": "crypto-bigint", "version": "0.5.5", "source": REGISTRY, "checksum": "a" * 64}
ADVISORY = "RUSTSEC-2026-0387"


def policy():
    return {
        "packages": {"crypto-bigint": {k: v for k, v in PACKAGE.items() if k != "name"}},
        "advisories": {ADVISORY: {"package": "crypto-bigint", "rationale": "exact reviewed operations"}},
    }


def report():
    return {"settings": {"ignore": []}, "warnings": {}, "vulnerabilities": [
        {"advisory": {"id": ADVISORY, "package": "crypto-bigint"}, "package": copy.deepcopy(PACKAGE)},
    ]}


class DependencyReviewTests(unittest.TestCase):
    def test_only_exact_reviewed_finding_is_accepted(self):
        accepted, remaining = review.filter_report(report(), policy(), "deny", set())
        self.assertEqual(len(accepted), 1)
        self.assertEqual(remaining, [])

    def test_unknown_finding_remains_a_failure(self):
        data = report()
        data["vulnerabilities"][0]["advisory"]["id"] = "RUSTSEC-2099-0001"
        accepted, remaining = review.filter_report(data, policy(), "deny", set())
        self.assertEqual(accepted, [])
        self.assertEqual(len(remaining), 1)

    def test_version_source_and_checksum_drift_fail(self):
        for key, value in [("version", "0.5.6"), ("source", "git+unreviewed"), ("checksum", "b" * 64)]:
            with self.subTest(key=key):
                data = report()
                data["vulnerabilities"][0]["package"][key] = value
                with self.assertRaises(ValueError):
                    review.filter_report(data, policy(), "deny", set())

    def test_global_ignores_fail(self):
        data = report()
        data["settings"]["ignore"] = [ADVISORY]
        with self.assertRaises(ValueError):
            review.filter_report(data, policy(), "deny", set())

    def test_unknown_warning_category_fails(self):
        data = report()
        data["warnings"] = {"future_unknown_category": []}
        with self.assertRaises(ValueError):
            review.filter_report(data, policy(), "deny", set())

    def test_unsound_findings_are_not_discarded_as_warnings(self):
        data = report()
        data["warnings"] = {"unsound": data["vulnerabilities"]}
        data["vulnerabilities"] = []
        self.assertEqual(len(review.filter_report(data, policy(), "deny", set())[0]), 1)

    def test_scanner_operational_errors_fail(self):
        diagnostic = {"fields": {"severity": "error", "code": "license-rejected"}}
        with self.assertRaises(ValueError):
            review.deny_diagnostics(json.dumps(diagnostic))

    def test_host_and_compiler_overrides_fail(self):
        review.validate_host({}, "Linux", "x86_64")
        for env, system, machine in [({}, "Darwin", "arm64"),
                ({"RUSTFLAGS": "-Ctarget-cpu=native"}, "Linux", "x86_64"),
                ({"CARGO_BUILD_TARGET": "other"}, "Linux", "x86_64")]:
            with self.subTest(env=env, system=system):
                with self.assertRaises(ValueError):
                    review.validate_host(env, system, machine)

    def test_new_secret_arithmetic_features_fail(self):
        for name, feature in [("aws-sigv4", "sigv4a"), ("der", "bigint"), ("crypto-bigint", "alloc")]:
            metadata = {"packages": [{"id": "p", "name": name}],
                        "resolve": {"nodes": [{"id": "p", "features": [feature]}]}}
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    review.validate_features(metadata)

    def test_changed_advisory_text_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "crates/crypto-bigint" / f"{ADVISORY}.md"
            path.parent.mkdir(parents=True)
            path.write_text("reviewed record")
            data = policy()
            data["advisories"][ADVISORY]["sha256"] = review.digest(path.read_bytes())
            review.validate_advisories(root, data)
            path.write_text("updated mechanism")
            with self.assertRaises(ValueError):
                review.validate_advisories(root, data)

    def test_source_and_untracked_caller_drift_change_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "lib.rs").write_text("original caller")
            initial = review.source_fingerprint(root)
            (root / "lib.rs").write_text("new signing call")
            self.assertNotEqual(initial, review.source_fingerprint(root))
            (root / "lib.rs").write_text("original caller")
            (root / "new.rs").write_text("new exposed caller")
            self.assertNotEqual(initial, review.source_fingerprint(root))

    def test_context_rejects_lock_graph_compiler_or_target_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "Cargo.lock").write_text("[[package]]\n" + "\n".join(
                f"{key} = {json.dumps(value)}" for key, value in PACKAGE.items()))
            metadata = {"packages": [{**PACKAGE, "id": "p"}],
                        "resolve": {"nodes": [{"id": "p", "features": [], "deps": []}]}}
            scope = {**policy(), "manifest": "Cargo.toml", "target": review.HOST,
                     **review.fingerprints(root, "workspace", metadata)}
            data = {"schema": 1, "host": review.HOST, "rustc_commit": "expected",
                    "scopes": {"workspace": scope}}
            review.validate_context(root, data, "workspace", metadata, "commit-hash: expected\n")
            for field in ["lock_sha256", "source_sha256", "graph_sha256", "target"]:
                changed = copy.deepcopy(data)
                changed["scopes"]["workspace"][field] = "unreviewed"
                with self.subTest(field=field):
                    with self.assertRaises(ValueError):
                        review.validate_context(root, changed, "workspace", metadata, "commit-hash: expected\n")
            with self.assertRaises(ValueError):
                review.validate_context(root, data, "workspace", metadata, "commit-hash: different\n")


if __name__ == "__main__":
    unittest.main()
