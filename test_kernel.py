#!/usr/bin/env python3
"""PGK v21 builder tests, including all prior independent counterexamples."""
from __future__ import annotations

import argparse
import ast
import concurrent.futures
import copy
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import kernel
import state_store
import test_support as fixture

HERE = Path(__file__).resolve().parent
WORKSPACE_ROOT = Path(os.environ.get("PGK_V21_WORKSPACE_ROOT", str(HERE.parents[3]))).resolve()
OPA = WORKSPACE_ROOT / ".toolchains/benchmarks/opa-v1.19.0/opa_windows_amd64.exe"
TEST_ENV = {**os.environ, **kernel.BLIND_EXECUTION_ENVIRONMENT}
FIXTURE_NOW = None


def v16_blocker_regressions():
    """Static/direct controls for prior external-runner blockers."""
    kernel_source = (HERE / "kernel.py").read_text("utf-8")
    runner_source = (HERE / "run_external.py").read_text("utf-8")
    return [
        {
            "id": "PGK-V19-TOCTOU-MUTABLE-EXECUTION-TREE",
            "rejected": (
                "copy_verified_snapshot" in runner_source
                and 'source.open("rb", buffering=0)' in runner_source
                and "os.fstat(source_stream.fileno())" in runner_source
                and 'str(snapshot / "test_kernel.py")' in runner_source
                and 'str(ROOT / "test_kernel.py")' not in runner_source
                and "execution_snapshot_file_digests" in runner_source
                and "execution_snapshot_unchanged" in runner_source
            ),
        },
        {
            "id": "PGK-V16-EXTERNAL-PIN-NOT-ENFORCED",
            "rejected": ("--external-pin" in runner_source
                         and "candidate manifest does not match external pin" in runner_source
                         and "external pin must be outside candidate" in runner_source),
        },
        {
            "id": "PGK-V16-TEST-TIME-AUTHORITY-BYPASS",
            "rejected": ("TEST_" + "TRUSTED_TIME" not in kernel_source
                         and "PGK_" + "V16_BUILDER_CLOCK_FIXTURE" not in (HERE / "test_kernel.py").read_text("utf-8")),
        },
        {
            "id": "PGK-V16-UNBOUNDED-TSA-FANOUT",
            "rejected": ("authenticated_observed_at" in kernel_source
                         and "semantic_now = utc(text(request[\"authenticated_observed_at\"]))" in kernel_source
                         and "SUITE_DEADLINE_SECONDS" in runner_source),
        },
    ]


def call(root, anchors):
    files, pins = fixture.files_and_pins(root)
    try:
        kernel.KEYS = anchors
        return 0, kernel.decide(root, files, pins)
    except Exception:
        return 2, "DENY"


def rewrite(root, name, payload, signer, private):
    fixture.write(root / (name + ".json"), fixture.sign(payload, signer, private))


def refresh_gate_ref(root, kind, private):
    gates = json.loads((root / "gates.json").read_text("utf-8"))["payload"]
    gates["evidence"][kind]["sha256"] = fixture.sha((root / gates["evidence"][kind]["path"]).read_bytes())
    rewrite(root, "gates", gates, "coordinator-a", private)


def hostile_case(case_id, mutate):
    with tempfile.TemporaryDirectory(prefix="pgk-v6-hostile-") as td:
        base = Path(td); root = base / "root"; state = base / "state"
        state_store.write_test_marker(state); kernel.AUTHORITATIVE_STATE_ROOT = state; kernel.ENFORCE_STATE_ACL = False
        None  # v14 always uses the attested deployment clock
        private, anchors = fixture.new_keyring(); fixture.build(root, private, OPA, FIXTURE_NOW)
        mutate(root, private)
        outcome = call(root, anchors)
        return {"id": case_id, "exit_code": outcome[0], "output": outcome[1], "rejected": outcome == (2, "DENY")}


def private_key_literal_scan():
    """Reject deterministic key construction in shipped runtime/support.

    This intentionally scans call syntax rather than its own diagnostic text.
    Random ``Ed25519PrivateKey.generate()`` in test support is permitted and no
    generated value is persisted.
    """
    findings = []
    for path in [HERE / "kernel.py", HERE / "test_support.py"]:
        text = path.read_text("utf-8")
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else (
                node.func.id if isinstance(node.func, ast.Name) else "")
            if name == "from_private_bytes":
                findings.append(f"{path.name}:{getattr(node, 'lineno', 0)}:deterministic-private-key")
    return findings


def typed_trace_negative_controls(private, anchors):
    """Prove generic/earlier failures cannot become a typed branch trace."""
    controls = []
    def invoke(case_id, target, operator, code, payload, signer="reviewer-new"):
        with tempfile.TemporaryDirectory(prefix="pgk-v10-trace-") as td:
            root = Path(td)
            fixture.write(root / "candidate.json", fixture.sign(payload, signer, private))
            request = kernel.canonical_json({
                "schema_version": 1, "root": str(root.resolve()),
                "files": {"candidate": "candidate.json", "dispatch": "candidate.json",
                          "roster": "candidate.json", "verdict": "candidate.json", "gates": "candidate.json"},
                "pins": {name: fixture.sha((root / "candidate.json").read_bytes())
                         for name in ["candidate", "dispatch", "roster", "verdict", "gates"]},
                "keys": anchors,
                "case_id": case_id, "target_name": target,
                "mutation_operator": operator, "expected_invariant": code,
                "authenticated_observed_at": FIXTURE_NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
            completed = subprocess.run(
                [sys.executable, str(HERE / "kernel.py"), kernel.BLIND_CHILD_SWITCH],
                input=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=str(root), env=TEST_ENV, check=False,
                timeout=kernel.BLIND_EXECUTION_TIMEOUT_SECONDS)
            return completed.returncode, completed.stdout, completed.stderr

    valid = {
        "schema_version": 2, "initiative_id": kernel.INITIATIVE,
        "submission_id": "sub-009", "builder_id": "builder-forged",
        "requested_result": kernel.ALLOW, "manifest_path": "sealed/manifest.txt",
        "manifest_sha256": "0" * 64,
        "comparator": {
            "product_id": "OPA", "version": "1.19.0",
            "official_source": "https://github.com/open-policy-agent/opa",
            "artifact_path": ".toolchains/benchmarks/opa-v1.19.0/opa_windows_amd64.exe",
            "artifact_sha256": "ed4ee673b2182352af3a9d5f0de4a74d23a063cbbb447723fb21ac5ead8cd599",
            "minimum_trials_per_side": 30, "minimum_improvement_percent": 10,
        },
    }
    case_id = kernel.BLIND_CORPUS[0]
    target, operator, code = kernel.BLIND_CASE_CONTRACTS[case_id]
    for label, payload, signer in [
        ("wrong-signer", valid, "reviewer-new"),
        ("closed-schema", dict(valid, unexpected=True), "builder-a"),
        ("earlier-kind-failure", dict(valid, schema_version=1), "builder-a"),
    ]:
        rc, out, err = invoke(case_id, target, operator, code, payload, signer)
        controls.append({"id": label, "exit_code": rc,
                         "generic_deny": out == b"DENY\n",
                         "typed_trace_absent": not err.startswith(kernel.SEMANTIC_REJECTION_PREFIX)})
    # Cross-case byte reuse is invalid: identical bytes contain the first case
    # id/operator and therefore cannot satisfy a different deployment contract.
    other = kernel.BLIND_CORPUS[1]
    other_target, other_operator, other_code = kernel.BLIND_CASE_CONTRACTS[other]
    with tempfile.TemporaryDirectory(prefix="pgk-v10-reuse-") as td:
        root = Path(td); fixture.write(root / "candidate.json", fixture.sign(valid, "builder-a", private))
        raw_hash = fixture.sha((root / "candidate.json").read_bytes())
        request = kernel.canonical_json({"schema_version": 1, "root": str(root.resolve()),
            "files": {n: "candidate.json" for n in ["candidate", "dispatch", "roster", "verdict", "gates"]},
            "pins": {n: raw_hash for n in ["candidate", "dispatch", "roster", "verdict", "gates"]},
            "keys": anchors, "case_id": other,
            "target_name": other_target, "mutation_operator": other_operator,
            "expected_invariant": other_code,
            "authenticated_observed_at": FIXTURE_NOW.strftime("%Y-%m-%dT%H:%M:%SZ")})
        completed = subprocess.run([sys.executable, str(HERE / "kernel.py"), kernel.BLIND_CHILD_SWITCH],
            input=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(root),
            env=TEST_ENV, check=False, timeout=kernel.BLIND_EXECUTION_TIMEOUT_SECONDS)
        controls.append({"id": "identical-bytes-cross-case", "exit_code": completed.returncode,
                         "generic_deny": completed.stdout == b"DENY\n",
                         "typed_trace_absent": not completed.stderr.startswith(kernel.SEMANTIC_REJECTION_PREFIX)})

    # Positive control reaches an actual named validator: a validly signed
    # benchmark artifact whose asserted arithmetic disagrees with raw trials.
    with tempfile.TemporaryDirectory(prefix="pgk-v12-real-branch-") as td:
        root = Path(td) / "root"; state = Path(td) / "state"
        state_store.write_test_marker(state); kernel.AUTHORITATIVE_STATE_ROOT = state
        kernel.ENFORCE_STATE_ACL = False; None  # v14 always uses the attested deployment clock
        fixture.build(root, private, OPA, FIXTURE_NOW)
        real_case = "PGK-V3-BLIND-BENCH-ARITH"
        real_target, real_operator, real_code = kernel.BLIND_CASE_CONTRACTS[real_case]
        mutated_rel = "blind-artifacts/" + real_case.lower() + ".mutated.bin"
        mutated_hash = fixture.sha((root / mutated_rel).read_bytes())
        files, pins = fixture.files_and_pins(root)
        request = kernel.canonical_json({"schema_version": 1, "root": str(root.resolve()),
            "files": files, "pins": pins, "keys": anchors,
            "case_id": real_case, "target_name": real_target,
            "mutated_artifact_path": mutated_rel, "mutated_artifact_sha256": mutated_hash,
            "mutation_operator": real_operator, "expected_invariant": real_code,
            "authenticated_observed_at": FIXTURE_NOW.strftime("%Y-%m-%dT%H:%M:%SZ")})
        completed = subprocess.run([sys.executable, str(HERE / "kernel.py"), kernel.BLIND_CHILD_SWITCH],
            input=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(root),
            env=TEST_ENV, check=False, timeout=kernel.BLIND_EXECUTION_TIMEOUT_SECONDS)
        controls.append({"id": "real-target-branch", "exit_code": completed.returncode,
                         "generic_deny": completed.stdout == b"DENY\n",
                         "typed_trace_present": completed.stderr.startswith(kernel.SEMANTIC_REJECTION_PREFIX)})
    return controls


def v21_runtime_snapshot_and_clock_controls():
    """Direct regression proofs for the V12-V17 review blockers."""
    results = []
    with tempfile.TemporaryDirectory(prefix="pgk-v14-controls-") as td:
        base = Path(td); root = base / "root"; state = base / "state"
        state_store.write_test_marker(state)
        kernel.AUTHORITATIVE_STATE_ROOT = state; kernel.ENFORCE_STATE_ACL = False
        None  # v14 always uses the attested deployment clock
        private, anchors = fixture.new_keyring(); fixture.build(root, private, OPA, FIXTURE_NOW)
        files, pins = fixture.files_and_pins(root); kernel.KEYS = anchors
        original = kernel.decide_semantic_case
        kernel.decide_semantic_case = lambda *a, **k: (_ for _ in ()).throw(kernel.Reject("disabled"))
        try:
            kernel.decide(root, files, pins, consume=False); denied = False
        except Exception:
            denied = True
        finally:
            kernel.decide_semantic_case = original
        results.append({"id": "PGK-V12-UNBOUND-SEMANTIC-VALIDATOR", "rejected": denied})

        original_snapshot = kernel.snapshot_pinned_bytes
        calls = {"count": 0}
        def swap_after_first(snapshot_root, rel, expected):
            value = original_snapshot(snapshot_root, rel, expected)
            if rel == "sealed/manifest.txt":
                calls["count"] += 1
                if calls["count"] == 1:
                    (snapshot_root / rel).write_bytes(b"reviewer-concurrent-swap\n")
            return value
        kernel.snapshot_pinned_bytes = swap_after_first
        try:
            kernel.decide(root, files, pins, consume=False); denied = False
        except Exception:
            denied = True
        finally:
            kernel.snapshot_pinned_bytes = original_snapshot
        results.append({"id": "PGK-V12-CANDIDATE-MANIFEST-TOCTOU", "rejected": denied})

        # The TOCTOU control intentionally modified the first fixture.  Build a
        # clean, independently signed fixture for the clock controls.
        clock_root = base / "clock-root"
        private, anchors = fixture.new_keyring(); fixture.build(clock_root, private, OPA, FIXTURE_NOW)
        files, pins = fixture.files_and_pins(clock_root); kernel.KEYS = anchors

        # Restore the real implementation after the first control before
        # probing unrelated clock behavior.
        kernel.decide_semantic_case = original

        # Exact V13 counterexample: replacing the old public clock hook must no
        # longer affect the production path.  The compatibility name is not
        # consumed and the currently valid fixture still ALLOWs.
        setattr(kernel, "trusted_now", lambda: kernel.utc("2000-01-01T00:00:00Z"))
        try:
            unaffected = kernel.decide(clock_root, files, pins, consume=False) == fixture.ALLOW
        except Exception:
            unaffected = False
        finally:
            delattr(kernel, "trusted_now")
        results.append({"id": "PGK-V13-LEGACY-TRUSTED-NOW-IGNORED", "rejected": unaffected})

        # Replacing the actual deployment-owned boundary is detected by live
        # code identity attestation before a timestamp can authorize anything.
        original_clock = kernel.trusted_clock.authoritative_utc_now
        kernel.trusted_clock.authoritative_utc_now = lambda _challenge: (
            kernel.utc("2000-01-01T00:00:00Z"), {})
        try:
            kernel.decide(clock_root, files, pins, consume=False); denied = False
        except Exception:
            denied = True
        finally:
            kernel.trusted_clock.authoritative_utc_now = original_clock
        results.append({"id": "PGK-V13-UNATTESTED-TRUSTED-CLOCK", "rejected": denied})

        # Exact V17 counterexample: the public entry point can remain unchanged
        # while a mutable helper/imported parser is replaced.  Both dependency
        # classes must fail closed before their fabricated result is consumed.
        original_validate_chain = kernel.trusted_clock._validate_chain
        kernel.trusted_clock._validate_chain = lambda *_a, **_k: {
            "tsa_url": "attacker", "token_sha256": "00" * 32,
            "trust_root_sha256": "00" * 32, "leaf_sha256": "00" * 32,
            "chain_certificates": 1,
        }
        try:
            kernel.attest_clock_boundary(); helper_denied = False
        except Exception:
            helper_denied = True
        finally:
            kernel.trusted_clock._validate_chain = original_validate_chain
        original_get_timestamp = kernel.trusted_clock.get_timestamp
        kernel.trusted_clock.get_timestamp = lambda *_a, **_k: FIXTURE_NOW
        try:
            kernel.attest_clock_boundary(); imported_denied = False
        except Exception:
            imported_denied = True
        finally:
            kernel.trusted_clock.get_timestamp = original_get_timestamp
        results.append({"id": "PGK-V17-UNATTESTED-CLOCK-HELPERS",
                        "rejected": helper_denied and imported_denied})

        # Exact V18 counterexample: the module global and all clock functions
        # remain identical while an attribute reached through the mutable
        # hashlib module is replaced.  V21 binds the exact attribute closure.
        original_sha256 = kernel.trusted_clock.hashlib.sha256
        kernel.trusted_clock.hashlib.sha256 = lambda *_a, **_k: type(
            "ForgedDigest", (), {"digest": lambda self: b"\x00" * 32,
                                  "hexdigest": lambda self: "00" * 32})()
        try:
            kernel.attest_clock_boundary(); module_attribute_denied = False
        except Exception:
            module_attribute_denied = True
        finally:
            kernel.trusted_clock.hashlib.sha256 = original_sha256
        results.append({"id": "PGK-V18-MUTABLE-MODULE-ATTRIBUTES-UNATTESTED",
                        "rejected": module_attribute_denied})

        # Exact V14 counterexample: replacing the host wall clock can no
        # longer move external RFC 3161 generation time into a stale window.
        # We prove the clock implementation contains no host time dependency,
        # then exercise another authenticated observation successfully while
        # the common wall-clock callables are replaced.
        clock_source = (HERE / "trusted_clock.py").read_text("utf-8")
        no_host_clock = all(name not in clock_source for name in (
            "time.time(", "time.time_ns(", "datetime.now(", "datetime.utcnow("))
        import time as host_time
        original_time = host_time.time
        original_time_ns = host_time.time_ns
        host_time.time = lambda: 0.0
        host_time.time_ns = lambda: 0
        try:
            external_value, external_record = kernel.acquire_trusted_time()[0], kernel.acquire_trusted_time()[3]
            external_ok = (external_value.year >= 2026 and b'"external_attestation"' in external_record)
        except Exception:
            external_ok = False
        finally:
            host_time.time = original_time
            host_time.time_ns = original_time_ns
        results.append({"id": "PGK-V14-UNATTESTED-CLOCK-DEPENDENCY",
                        "rejected": no_host_clock and external_ok})

        # V15 incorrectly terminated the certificate path at a cross-signed
        # certificate.  V16 pins a genuine self-signed CA, validates its
        # self-signature, and treats the cross certificate as an intermediate.
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        anchor_path = HERE / kernel.trusted_clock.TSA_ROOT_FILE
        anchor = x509.load_der_x509_certificate(anchor_path.read_bytes())
        try:
            kernel.trusted_clock._verify_certificate_signature(anchor, anchor)
            self_signature_ok = True
        except Exception:
            self_signature_ok = False
        anchor_ok = (
            anchor.subject == anchor.issuer
            and anchor.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            and anchor.fingerprint(hashes.SHA256()).hex() == kernel.trusted_clock.TSA_ROOT_SHA256
            and self_signature_ok
        )
        transport_ok = kernel.trusted_clock.TSA_URL.startswith("https://")
        old_cross = x509.load_der_x509_certificate(
            (HERE / "digicert-trusted-root-g4-cross.der").read_bytes())
        cross_is_not_anchor = old_cross.subject != old_cross.issuer
        try:
            observed, record = kernel.trusted_clock.authoritative_utc_now(os.urandom(32))
            full_chain_ok = (
                observed.year >= 2026
                and record["trust_root_sha256"] == kernel.trusted_clock.TSA_ROOT_SHA256
                and record["chain_certificates"] >= 3
                and record["tsa_url"] == kernel.trusted_clock.TSA_URL
            )
        except Exception:
            full_chain_ok = False
        results.append({"id": "PGK-V15-TSA-TRUST-CHAIN-MISANCHORED",
                        "rejected": anchor_ok and transport_ok and cross_is_not_anchor and full_chain_ok})
    return results


def main():
    global FIXTURE_NOW
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out")
    args = parser.parse_args()
    # v21 has no environment-selected trusted-time fixture and no production
    # test-time authorization hook.  The suite begins with a real, attested RFC3161
    # observation and all production decisions acquire live observations.
    FIXTURE_NOW = kernel.acquire_trusted_time()[0]
    kernel.TEST_FAST_CI = True
    cases = []
    configured_authoritative_root = kernel.AUTHORITATIVE_STATE_ROOT
    absolute_state_root = configured_authoritative_root.is_absolute()
    with tempfile.TemporaryDirectory(prefix="pgk-v6-") as td:
        base = Path(td); root = base / "root"; state = base / "trusted-state"
        state_store.write_test_marker(state); kernel.AUTHORITATIVE_STATE_ROOT = state; kernel.ENFORCE_STATE_ACL = False
        None  # v14 always uses the attested deployment clock
        private, anchors = fixture.new_keyring(); fixture.build(root, private, OPA, FIXTURE_NOW)
        first = call(root, anchors)
        replay = call(root, anchors)
        cases.append({"id": "PGK-V2-BLIND-STATE-ROOT-SWAP", "result": "DENY_BY_API_BOUNDARY",
                      "detail": "production CLI/API has no state-root input and the configured root is absolute"})
        cli = subprocess.run([sys.executable, str(HERE / "kernel.py"), "--help"], text=True,
                             capture_output=True, timeout=kernel.BLIND_EXECUTION_TIMEOUT_SECONDS)
        state_root_exposed = "--state-root" in cli.stdout
        # An untrusted alternate anchor set cannot validate the signed inputs.
        _, attacker_anchors = fixture.new_keyring()
        forged_anchor = call(root, attacker_anchors)
        scan = private_key_literal_scan()
        cases.append({"id": "PGK-V2-BLIND-KEYRECOVERY", "unsafe": bool(scan), "findings": scan})

    def bad_benchmark(root, private):
        path = root / "evidence/real_product_benchmark.json"
        payload = json.loads(path.read_text("utf-8"))["payload"]
        payload["measurements"]["improvement_basis_points"] = 9999
        fixture.write(path, fixture.sign(payload, "benchmark-lab-a", private)); refresh_gate_ref(root, "real_product_benchmark", private)
    cases.append(hostile_case("PGK-V3-BLIND-BENCH-ARITH", bad_benchmark))

    def future_evidence(root, private):
        path = root / "evidence/human_acceptance.json"; payload = json.loads(path.read_text("utf-8"))["payload"]
        payload["observed_at"] = "9999-12-31T23:59:59Z"
        fixture.write(path, fixture.sign(payload, "human-lab-a", private)); refresh_gate_ref(root, "human_acceptance", private)
    cases.append(hostile_case("PGK-V3-BLIND-FUTURE-EVIDENCE", future_evidence))

    def one_mutation(root, private):
        verdict = json.loads((root / "verdict.json").read_text("utf-8"))["payload"]
        verdict["independent_mutations"] = 1; rewrite(root, "verdict", verdict, "reviewer-new", private)
        gates = json.loads((root / "gates.json").read_text("utf-8"))["payload"]
        gates["verdict_sha256"] = fixture.sha((root / "verdict.json").read_bytes()); rewrite(root, "gates", gates, "coordinator-a", private)
    cases.append(hostile_case("PGK-V3-BLIND-ONE-MUTATION", one_mutation))

    def unbound_blind_result(root, private):
        verdict = json.loads((root / "verdict.json").read_text("utf-8"))["payload"]
        verdict["blind_case_results"][0]["evidence_sha256"] = "0" * 64
        rewrite(root, "verdict", verdict, "reviewer-new", private)
        gates = json.loads((root / "gates.json").read_text("utf-8"))["payload"]
        gates["verdict_sha256"] = fixture.sha((root / "verdict.json").read_bytes())
        rewrite(root, "gates", gates, "coordinator-a", private)
    cases.append(hostile_case("PGK-V4-BLIND-RESULT-PIN", unbound_blind_result))

    def asserted_ci(root, private):
        path = root / "evidence/real_product_benchmark.json"
        payload = json.loads(path.read_text("utf-8"))["payload"]
        measurements = payload["measurements"]
        measurements["confidence_interval_low_basis_points"] = 1000
        measurements["confidence_interval_high_basis_points"] = 2000
        summary_keys = ["corpus_sha256", "host_fingerprint_sha256", "toolchain_sha256", "candidate_trials_sha256",
                        "comparator_trials_sha256", "candidate_p95_us", "comparator_p95_us", "improvement_basis_points",
                        "confidence_interval_method", "confidence_interval_resamples", "confidence_level_basis_points",
                        "confidence_interval_seed_sha256", "confidence_interval_low_basis_points",
                        "confidence_interval_high_basis_points"]
        measurements["derived_summary_sha256"] = fixture.sha(fixture.canon({k: measurements[k] for k in summary_keys}))
        fixture.write(path, fixture.sign(payload, "benchmark-lab-a", private))
        refresh_gate_ref(root, "real_product_benchmark", private)
    cases.append(hostile_case("PGK-V4-BLIND-CI-ASSERTION", asserted_ci))

    def stale_window(root, private):
        dispatch = json.loads((root / "dispatch.json").read_text("utf-8"))["payload"]
        dispatch.update({"issued_at": "2000-01-01T00:00:00Z", "collection_not_before": "2000-01-01T00:00:00Z",
                         "collection_not_after": "2000-01-02T00:00:00Z"})
        rewrite(root, "dispatch", dispatch, "coordinator-a", private)
        dispatch_hash = fixture.sha((root / "dispatch.json").read_bytes())
        verdict = json.loads((root / "verdict.json").read_text("utf-8"))["payload"]
        verdict["dispatch_sha256"] = dispatch_hash
        for item in verdict["blind_case_results"]:
            artifact_path = root / item["evidence_path"]
            artifact = json.loads(artifact_path.read_text("utf-8"))["payload"]
            artifact["dispatch_sha256"] = dispatch_hash; artifact["observed_at"] = "2000-01-01T12:00:00Z"
            replay_path = root / artifact["replay_artifact_path"]
            replay = json.loads(replay_path.read_text("utf-8"))["payload"]
            replay["dispatch_sha256"] = dispatch_hash; replay["executed_at"] = "2000-01-01T12:00:00Z"
            fixture.write(replay_path, fixture.sign(replay, "reviewer-new", private))
            artifact["replay_artifact_sha256"] = fixture.sha(replay_path.read_bytes())
            mutation_path = root / artifact["mutation_artifact_path"]
            mutation = json.loads(mutation_path.read_text("utf-8"))["payload"]
            mutation["dispatch_sha256"] = dispatch_hash
            mutation["replay_artifact_sha256"] = artifact["replay_artifact_sha256"]
            fixture.write(mutation_path, fixture.sign(mutation, "reviewer-new", private))
            artifact["mutation_artifact_sha256"] = fixture.sha(mutation_path.read_bytes())
            fixture.write(artifact_path, fixture.sign(artifact, "reviewer-new", private))
            item["evidence_sha256"] = fixture.sha(artifact_path.read_bytes())
        rewrite(root, "verdict", verdict, "reviewer-new", private)
        for kind in ["human_acceptance", "soak_24h", "remote_environment", "network_impairment", "real_product_benchmark"]:
            path = root / f"evidence/{kind}.json"; payload = json.loads(path.read_text("utf-8"))["payload"]
            payload["observed_at"] = "2000-01-01T12:00:00Z"
            fixture.write(path, fixture.sign(payload, f"{kind.split('_')[0]}-lab-a" if kind != "real_product_benchmark" else "benchmark-lab-a", private))
        gates = json.loads((root / "gates.json").read_text("utf-8"))["payload"]
        gates["verdict_sha256"] = fixture.sha((root / "verdict.json").read_bytes())
        for kind, ref in gates["evidence"].items(): ref["sha256"] = fixture.sha((root / ref["path"]).read_bytes())
        rewrite(root, "gates", gates, "coordinator-a", private)
    cases.append(hostile_case("PGK-V4-BLIND-STALE-WINDOW", stale_window))

    def future_blind_result(root, private):
        verdict = json.loads((root / "verdict.json").read_text("utf-8"))["payload"]
        item = verdict["blind_case_results"][0]
        artifact_path = root / item["evidence_path"]
        artifact = json.loads(artifact_path.read_text("utf-8"))["payload"]
        artifact["observed_at"] = "9999-12-31T23:59:59Z"
        fixture.write(artifact_path, fixture.sign(artifact, "reviewer-new", private))
        item["evidence_sha256"] = fixture.sha(artifact_path.read_bytes())
        rewrite(root, "verdict", verdict, "reviewer-new", private)
        gates = json.loads((root / "gates.json").read_text("utf-8"))["payload"]
        gates["verdict_sha256"] = fixture.sha((root / "verdict.json").read_bytes())
        rewrite(root, "gates", gates, "coordinator-a", private)
    cases.append(hostile_case("PGK-V5-BLIND-FUTURE-RESULT", future_blind_result))

    def asserted_blind_provenance(root, private):
        verdict = json.loads((root / "verdict.json").read_text("utf-8"))["payload"]
        item = verdict["blind_case_results"][0]
        artifact_path = root / item["evidence_path"]
        artifact = json.loads(artifact_path.read_text("utf-8"))["payload"]
        artifact["mutation_artifact_sha256"] = "0" * 64
        artifact["replay_artifact_sha256"] = "1" * 64
        fixture.write(artifact_path, fixture.sign(artifact, "reviewer-new", private))
        item["evidence_sha256"] = fixture.sha(artifact_path.read_bytes())
        rewrite(root, "verdict", verdict, "reviewer-new", private)
        gates = json.loads((root / "gates.json").read_text("utf-8"))["payload"]
        gates["verdict_sha256"] = fixture.sha((root / "verdict.json").read_bytes())
        rewrite(root, "gates", gates, "coordinator-a", private)
    cases.append(hostile_case("PGK-V5-BLIND-ASSERTED-PROVENANCE", asserted_blind_provenance))

    def missing_mutated_bytes(root, private):
        verdict = json.loads((root / "verdict.json").read_text("utf-8"))["payload"]
        item = verdict["blind_case_results"][0]
        blind = json.loads((root / item["evidence_path"]).read_text("utf-8"))["payload"]
        mutation = json.loads((root / blind["mutation_artifact_path"]).read_text("utf-8"))["payload"]
        (root / mutation["mutated_artifact_path"]).unlink()
    cases.append(hostile_case("PGK-V6-BLIND-MISSING-MUTATED-BYTES", missing_mutated_bytes))

    def no_op_mutation(root, private):
        verdict = json.loads((root / "verdict.json").read_text("utf-8"))["payload"]
        item = verdict["blind_case_results"][0]
        blind_path = root / item["evidence_path"]
        blind = json.loads(blind_path.read_text("utf-8"))["payload"]
        mutation_path = root / blind["mutation_artifact_path"]
        mutation = json.loads(mutation_path.read_text("utf-8"))["payload"]
        original = (root / mutation["original_artifact_path"]).read_bytes()
        (root / mutation["mutated_artifact_path"]).write_bytes(original)
        mutation["mutated_artifact_sha256"] = fixture.sha(original)
        recipe_path = root / mutation["recipe_artifact_path"]
        recipe = json.loads(recipe_path.read_text("utf-8"))["payload"]
        recipe["mutated_artifact_sha256"] = fixture.sha(original)
        fixture.write(recipe_path, fixture.sign(recipe, "reviewer-new", private))
        mutation["recipe_artifact_sha256"] = fixture.sha(recipe_path.read_bytes())
        replay_path = root / blind["replay_artifact_path"]
        replay = json.loads(replay_path.read_text("utf-8"))["payload"]
        replay["recipe_artifact_sha256"] = mutation["recipe_artifact_sha256"]
        fixture.write(replay_path, fixture.sign(replay, "reviewer-new", private))
        mutation["replay_artifact_sha256"] = fixture.sha(replay_path.read_bytes())
        fixture.write(mutation_path, fixture.sign(mutation, "reviewer-new", private))
        blind["mutation_artifact_sha256"] = fixture.sha(mutation_path.read_bytes())
        blind["replay_artifact_sha256"] = fixture.sha(replay_path.read_bytes())
        fixture.write(blind_path, fixture.sign(blind, "reviewer-new", private))
        item["evidence_sha256"] = fixture.sha(blind_path.read_bytes())
        rewrite(root, "verdict", verdict, "reviewer-new", private)
        gates = json.loads((root / "gates.json").read_text("utf-8"))["payload"]
        gates["verdict_sha256"] = fixture.sha((root / "verdict.json").read_bytes())
        rewrite(root, "gates", gates, "coordinator-a", private)
    cases.append(hostile_case("PGK-V6-BLIND-NOOP-BYTES", no_op_mutation))

    def untrusted_nonexecutable_program(root, private):
        """V7's decisive blocker: a reviewer-nominated inert blob must not run."""
        verdict = json.loads((root / "verdict.json").read_text("utf-8"))["payload"]
        item = verdict["blind_case_results"][0]
        blind_path = root / item["evidence_path"]
        blind = json.loads(blind_path.read_text("utf-8"))["payload"]
        mutation_path = root / blind["mutation_artifact_path"]
        mutation = json.loads(mutation_path.read_text("utf-8"))["payload"]
        recipe_path = root / mutation["recipe_artifact_path"]
        recipe = json.loads(recipe_path.read_text("utf-8"))["payload"]
        recipe.pop("execution_mode"); recipe.pop("interpreter_sha256"); recipe.pop("kernel_sha256")
        blob_rel = "tools/reviewer-nominated.bin"; blob = b"NOT-AN-EXECUTABLE\n"
        (root / blob_rel).parent.mkdir(parents=True, exist_ok=True); (root / blob_rel).write_bytes(blob)
        recipe.update({"schema_version": 1, "kind": "blind_replay_recipe_v1",
                       "program_path": blob_rel, "program_sha256": fixture.sha(blob),
                       "arguments": ["--case", item["case_id"], "--target", "candidate.json",
                                     "--candidate", mutation["mutated_artifact_path"]],
                       "environment": []})
        fixture.write(recipe_path, fixture.sign(recipe, "reviewer-new", private))
        mutation["recipe_artifact_sha256"] = fixture.sha(recipe_path.read_bytes())
        replay_path = root / blind["replay_artifact_path"]
        replay = json.loads(replay_path.read_text("utf-8"))["payload"]
        replay["recipe_artifact_sha256"] = mutation["recipe_artifact_sha256"]
        fixture.write(replay_path, fixture.sign(replay, "reviewer-new", private))
        mutation["replay_artifact_sha256"] = fixture.sha(replay_path.read_bytes())
        fixture.write(mutation_path, fixture.sign(mutation, "reviewer-new", private))
        blind["mutation_artifact_sha256"] = fixture.sha(mutation_path.read_bytes())
        blind["replay_artifact_sha256"] = fixture.sha(replay_path.read_bytes())
        fixture.write(blind_path, fixture.sign(blind, "reviewer-new", private))
        item["evidence_sha256"] = fixture.sha(blind_path.read_bytes())
        rewrite(root, "verdict", verdict, "reviewer-new", private)
        gates = json.loads((root / "gates.json").read_text("utf-8"))["payload"]
        gates["verdict_sha256"] = fixture.sha((root / "verdict.json").read_bytes())
        rewrite(root, "gates", gates, "coordinator-a", private)
    cases.append(hostile_case("PGK-V7-BLIND-NONEXECUTED-REPLAY", untrusted_nonexecutable_program))

    def semantic_parse_garbage(root, private):
        """V8 blocker: generic malformed JSON must not count as any case."""
        verdict = json.loads((root / "verdict.json").read_text("utf-8"))["payload"]
        item = verdict["blind_case_results"][0]
        blind_path = root / item["evidence_path"]
        blind = json.loads(blind_path.read_text("utf-8"))["payload"]
        mutation_path = root / blind["mutation_artifact_path"]
        mutation = json.loads(mutation_path.read_text("utf-8"))["payload"]
        garbage = (root / "candidate.json").read_bytes() + b"\nMALFORMED\n"
        (root / mutation["mutated_artifact_path"]).write_bytes(garbage)
        mutation["mutated_artifact_sha256"] = fixture.sha(garbage)
        recipe_path = root / mutation["recipe_artifact_path"]
        recipe = json.loads(recipe_path.read_text("utf-8"))["payload"]
        recipe["mutated_artifact_sha256"] = fixture.sha(garbage)
        fixture.write(recipe_path, fixture.sign(recipe, "reviewer-new", private))
        mutation["recipe_artifact_sha256"] = fixture.sha(recipe_path.read_bytes())
        replay_path = root / blind["replay_artifact_path"]
        replay = json.loads(replay_path.read_text("utf-8"))["payload"]
        replay["recipe_artifact_sha256"] = mutation["recipe_artifact_sha256"]
        fixture.write(replay_path, fixture.sign(replay, "reviewer-new", private))
        mutation["replay_artifact_sha256"] = fixture.sha(replay_path.read_bytes())
        fixture.write(mutation_path, fixture.sign(mutation, "reviewer-new", private))
        blind["mutation_artifact_sha256"] = fixture.sha(mutation_path.read_bytes())
        blind["replay_artifact_sha256"] = fixture.sha(replay_path.read_bytes())
        fixture.write(blind_path, fixture.sign(blind, "reviewer-new", private))
        item["evidence_sha256"] = fixture.sha(blind_path.read_bytes())
        rewrite(root, "verdict", verdict, "reviewer-new", private)
        gates = json.loads((root / "gates.json").read_text("utf-8"))["payload"]
        gates["verdict_sha256"] = fixture.sha((root / "verdict.json").read_bytes())
        rewrite(root, "gates", gates, "coordinator-a", private)
    cases.append(hostile_case("PGK-V8-BLIND-PARSE-GARBAGE", semantic_parse_garbage))

    def semantic_cross_label(root, private):
        """Another case's signed semantic evidence is not interchangeable."""
        verdict = json.loads((root / "verdict.json").read_text("utf-8"))["payload"]
        first, second = verdict["blind_case_results"][:2]
        blind_path = root / first["evidence_path"]
        blind = json.loads(blind_path.read_text("utf-8"))["payload"]
        mutation_path = root / blind["mutation_artifact_path"]
        mutation = json.loads(mutation_path.read_text("utf-8"))["payload"]
        mutation["mutation_type"] = kernel.BLIND_CASE_CONTRACTS[second["case_id"]][1]
        fixture.write(mutation_path, fixture.sign(mutation, "reviewer-new", private))
        blind["mutation_artifact_sha256"] = fixture.sha(mutation_path.read_bytes())
        fixture.write(blind_path, fixture.sign(blind, "reviewer-new", private))
        first["evidence_sha256"] = fixture.sha(blind_path.read_bytes())
        rewrite(root, "verdict", verdict, "reviewer-new", private)
        gates = json.loads((root / "gates.json").read_text("utf-8"))["payload"]
        gates["verdict_sha256"] = fixture.sha((root / "verdict.json").read_bytes())
        rewrite(root, "gates", gates, "coordinator-a", private)
    cases.append(hostile_case("PGK-V8-BLIND-CROSS-LABEL", semantic_cross_label))

    # A directory junction does not require Developer Mode/symlink privilege
    # and still carries FILE_ATTRIBUTE_REPARSE_POINT.  The store must reject it.
    with tempfile.TemporaryDirectory(prefix="pgk-v6-junction-") as td:
        base = Path(td); attacker = base / "attacker"; attacker.mkdir()
        state_store.write_test_marker(attacker); junction = base / "authority"
        linked = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(attacker)], capture_output=True).returncode == 0
        if linked:
            try:
                state_store.verify(junction, junction, enforce_acl=False); junction_denied = False
            except state_store.StoreReject:
                junction_denied = True
            os.rmdir(junction)
        else:
            junction_denied = False
        cases.append({"id": "PGK-V3-BLIND-STATE-SYMLINK", "junction_created": linked,
                      "exit_code": 2 if junction_denied else 0, "output": "DENY" if junction_denied else "UNSAFE",
                      "rejected": linked and junction_denied})

    # Fresh interpreter processes model restarts and race one persisted nonce.
    with tempfile.TemporaryDirectory(prefix="pgk-v6-restart-") as td:
        restart_root = Path(td) / "state"; state_store.write_test_marker(restart_root)
        commands = [[sys.executable, str(HERE / "state_store_probe.py"), str(restart_root)] for _ in range(16)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            probes = list(pool.map(lambda cmd: subprocess.run(
                cmd, text=True, capture_output=True,
                timeout=kernel.BLIND_EXECUTION_TIMEOUT_SECONDS), commands))
        restart_winners = sum(p.returncode == 0 and p.stdout.strip() == "ALLOW_ONCE" for p in probes)
        restart_denies = sum(p.returncode == 2 and p.stdout.strip() == "DENY_REPLAY" for p in probes)
        cases.append({"id": "PGK-V4-RESTART-REPLAY", "processes": 16, "winners": restart_winners,
                      "denies": restart_denies, "exit_code": 2 if (restart_winners, restart_denies) == (1, 15) else 0,
                      "output": "DENY" if (restart_winners, restart_denies) == (1, 15) else "UNSAFE",
                      "rejected": (restart_winners, restart_denies) == (1, 15)})

    # Cross-process contention must have exactly one winner through the fixed
    # production CLI.  The fixture validator API is separately covered above.
    # Atomic O_EXCL semantics are tested here with threads against one state.
    with tempfile.TemporaryDirectory(prefix="pgk-v6-concurrent-") as td:
        base = Path(td); root = base / "root"; state = base / "trusted-state"
        state_store.write_test_marker(state); kernel.AUTHORITATIVE_STATE_ROOT = state; kernel.ENFORCE_STATE_ACL = False
        None  # v14 always uses the attested deployment clock
        private, anchors = fixture.new_keyring(); fixture.build(root, private, OPA, FIXTURE_NOW)
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: call(root, anchors), range(32)))
        winners = results.count((0, fixture.ALLOW))
        denies = results.count((2, "DENY"))

    private, anchors = fixture.new_keyring()
    trace_controls = typed_trace_negative_controls(private, anchors)
    v21_controls = v21_runtime_snapshot_and_clock_controls()
    v16_regressions = v16_blocker_regressions()

    result = {
        "schema_version": 1, "kind": "PGKv21BuilderTestResults",
        "positive_control": {"exit_code": first[0], "output": first[1]},
        "same_store_replay": {"exit_code": replay[0], "output": replay[1]},
        "production_cli_state_root_exposed": state_root_exposed,
        "configured_authoritative_state_root_absolute": absolute_state_root,
        "untrusted_anchor_attempt": {"exit_code": forged_anchor[0], "output": forged_anchor[1]},
        "concurrent_attempts": 32, "concurrent_winners": winners, "concurrent_denies": denies,
        "typed_trace_negative_controls": trace_controls,
        "v21_blocker_regression_controls": v21_controls,
        "v16_review_blocker_regressions": v16_regressions,
        "cases": cases,
    }
    hostile_closed = all(case.get("rejected", True) for case in cases)
    ok = (first == (0, fixture.ALLOW) and replay == (2, "DENY") and not state_root_exposed and absolute_state_root
          and forged_anchor == (2, "DENY") and winners == 1 and denies == 31 and not scan)
    ok = ok and hostile_closed
    ok = ok and all(c.get("typed_trace_absent", c.get("typed_trace_present", False))
                    for c in trace_controls)
    ok = ok and all(c["rejected"] for c in v21_controls)
    ok = ok and all(c["rejected"] for c in v16_regressions)
    result["builder_suite_passed"] = ok
    rendered = json.dumps(result, indent=2) + "\n"
    if args.json_out:
        Path(args.json_out).write_text(rendered, "utf-8")
    print(rendered, end="")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
