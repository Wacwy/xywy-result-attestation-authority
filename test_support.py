#!/usr/bin/env python3
"""Ephemeral fixture construction for PGK v21 tests.

No deterministic seed or private key is persisted.  Every invocation creates
a fresh keyring and injects only its public anchors into the validator API.
"""
from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import kernel

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ALLOW = "ALLOW_RECHARTER_SCHEDULING_ONLY"
IDS = [
    "CE-G3-ASSIGN-001", "CE-G3-DISPATCH-002", "CE-G3-PASS-003",
    "CE-G3-SOURCE-004", "CE-G3-FAILOPEN-005", "CE-G3-METHOD-006",
    "CE-G3-DECISION-007", "CE-G3-PERCENT-008", "CE-G3-COUNT-009",
    "CE-G3-SCHEMA-010",
]
ROLES = [
    "builder-a", "coordinator-a", "reviewer-new", "human-lab-a",
    "soak-lab-a", "remote-lab-a", "network-lab-a", "benchmark-lab-a",
]


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canon(value) + b"\n")


def new_keyring():
    private = {role: Ed25519PrivateKey.generate() for role in ROLES}
    anchors = {
        role: base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )).decode()
        for role, key in private.items()
    }
    return private, anchors


def sign(payload, signer, private):
    return {
        "schema_version": 1,
        "signer_id": signer,
        "payload": payload,
        "signature": base64.b64encode(private[signer].sign(canon(payload))).decode(),
    }


def build(root: Path, private, opa: Path, trusted_now=None):
    # Production never accepts caller-supplied time.  Test fixtures may reuse
    # one externally verified builder observation to avoid needless TSA load;
    # every actual kernel decision still acquires its own fresh tokens.
    now = (trusted_now or kernel.acquire_trusted_time()[0]).replace(microsecond=0)
    issued_at = now - dt.timedelta(hours=1)
    collection_after = now + dt.timedelta(days=1)
    observed_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    # Tests install only ephemeral public anchors; no private material enters
    # the runtime validator.
    kernel.KEYS = {
        role: base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )).decode()
        for role, key in private.items()
    }
    root.mkdir(parents=True, exist_ok=True)
    (root / "sealed").mkdir()
    (root / "evidence").mkdir()
    manifest = b"candidate-manifest-v10\n"
    (root / "sealed/manifest.txt").write_bytes(manifest)
    opa_rel = ".toolchains/benchmarks/opa-v1.19.0/opa_windows_amd64.exe"
    dest = root / opa_rel
    dest.parent.mkdir(parents=True)
    dest.write_bytes(opa.read_bytes())
    candidate = {
        "schema_version": 2, "initiative_id": "PGK-FAILCLOSED-001",
        "submission_id": "sub-009", "builder_id": "builder-a",
        "requested_result": ALLOW, "manifest_path": "sealed/manifest.txt",
        "manifest_sha256": sha(manifest),
        "comparator": {
            "product_id": "OPA", "version": "1.19.0",
            "official_source": "https://github.com/open-policy-agent/opa",
            "artifact_path": opa_rel, "artifact_sha256": sha(dest.read_bytes()),
            "minimum_trials_per_side": 30, "minimum_improvement_percent": 10,
        },
    }
    write(root / "candidate.json", sign(candidate, "builder-a", private))
    candidate_hash = sha((root / "candidate.json").read_bytes())
    roster = {
        "schema_version": 2, "initiative_id": "PGK-FAILCLOSED-001",
        "coordinators": ["coordinator-a"], "builders": ["builder-a"],
        "planners": ["planner-a"], "prior_reviewers": ["reviewer-old"],
        "eligible_reviewers": ["reviewer-new"],
        "gate_issuers": {
            "human_acceptance": "human-lab-a", "soak_24h": "soak-lab-a",
            "remote_environment": "remote-lab-a", "network_impairment": "network-lab-a",
            "real_product_benchmark": "benchmark-lab-a",
        },
    }
    write(root / "roster.json", sign(roster, "coordinator-a", private))
    dispatch = {
        "schema_version": 2, "initiative_id": "PGK-FAILCLOSED-001", "submission_id": "sub-009",
        "candidate_path": "candidate.json", "candidate_sha256": candidate_hash,
        "roster_path": "roster.json", "roster_sha256": sha((root / "roster.json").read_bytes()),
        "verdict_path": "verdict.json", "gates_path": "gates.json",
        "assigned_reviewer": "reviewer-new", "mandatory_replay": IDS,
        "mandatory_blind_replay": [
            "PGK-V2-BLIND-KEYRECOVERY", "PGK-V2-BLIND-STATE-ROOT-SWAP",
            "PGK-V3-BLIND-BENCH-ARITH", "PGK-V3-BLIND-FUTURE-EVIDENCE",
            "PGK-V3-BLIND-ONE-MUTATION", "PGK-V3-BLIND-STATE-SYMLINK",
            "PGK-V4-BLIND-RESULT-PIN", "PGK-V4-BLIND-CI-ASSERTION",
            "PGK-V4-BLIND-STALE-WINDOW",
            "PGK-V5-BLIND-FUTURE-RESULT", "PGK-V5-BLIND-ASSERTED-PROVENANCE",
        ],
        "minimum_blind_mutations": 11,
        "allowed_decisions": ["REWORK", "REJECT", "APPROVE_RECHARTER_ONLY"],
        "issued_at": issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "collection_not_before": issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "collection_not_after": collection_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce": "1234567890abcdef1234567890abcdef", "state_namespace": "pgk-v10-test",
    }
    write(root / "dispatch.json", sign(dispatch, "coordinator-a", private))
    verdict = {
        "schema_version": 2, "initiative_id": "PGK-FAILCLOSED-001", "submission_id": "sub-009",
        "candidate_sha256": candidate_hash, "dispatch_sha256": sha((root / "dispatch.json").read_bytes()),
        "reviewer_id": "reviewer-new", "decision": "APPROVE_RECHARTER_ONLY",
        "replayed_cases": IDS,
        "blind_case_results": [],
        "independent_mutations": 20, "unsafe_acceptances": 0,
    }
    interpreter_hash = sha(Path(sys.executable).resolve().read_bytes())
    kernel_hash = sha((Path(__file__).resolve().parent / "kernel.py").read_bytes())
    # Seed the verdict so case-specific signed verdict mutations can be built;
    # the final verdict with populated blind results replaces it below.
    write(root / "verdict.json", sign(verdict, "reviewer-new", private))
    seeded_verdict_bytes = (root / "verdict.json").read_bytes()
    (root / "blind-artifacts").mkdir(parents=True, exist_ok=True)
    (root / "semantic-targets").mkdir(parents=True, exist_ok=True)
    # Production-shaped semantic targets used by the frozen hostile corpus.
    state_root = {"schema_version": 1, "kind": "pgk_authoritative_state_root_v1",
                  "authoritative_root": str(kernel.AUTHORITATIVE_STATE_ROOT),
                  "resolved_root_sha256": sha(str(kernel.AUTHORITATIVE_STATE_ROOT.resolve()).encode())}
    write(root / "semantic-targets/state-root.json", sign(state_root, "coordinator-a", private))
    replay_probe = {"schema_version": 1, "kind": "blind_replay_pin_v1",
                    "case_id": "PGK-V4-BLIND-RESULT-PIN",
                    "recipe_artifact_path": "blind-recipes/pinned.json",
                    "recipe_artifact_sha256": "a" * 64, "actual_recipe_sha256": "a" * 64}
    write(root / "semantic-targets/blind-replay.json", sign(replay_probe, "reviewer-new", private))
    result_probe = {"schema_version": 1, "kind": "blind_result_time_v1",
                    "case_id": "PGK-V5-BLIND-FUTURE-RESULT", "observed_at": observed_at}
    write(root / "semantic-targets/blind-result.json", sign(result_probe, "reviewer-new", private))
    executed_rel = "semantic-targets/executed.bin"
    (root / executed_rel).write_bytes(b"executed-production-bytes-v12\n")
    provenance_probe = {"schema_version": 1, "kind": "executed_byte_provenance_v1",
                        "case_id": "PGK-V5-BLIND-ASSERTED-PROVENANCE",
                        "declared_executed_sha256": sha((root / executed_rel).read_bytes()),
                        "actual_executed_path": executed_rel,
                        "actual_executed_sha256": sha((root / executed_rel).read_bytes())}
    write(root / "semantic-targets/blind-mutation.json", sign(provenance_probe, "reviewer-new", private))
    # Evidence targets must exist before the semantic replay corpus is built.
    metrics = {
        "human_acceptance": {"participants": 30, "completed": 30, "blocking_defects": 0},
        "soak_24h": {"duration_seconds": 86400, "crashes": 0, "data_corruptions": 0},
        "remote_environment": {"sessions": 30, "completed": 30, "blocking_failures": 0},
        "network_impairment": {"profiles": ["latency-200ms", "loss-5pct", "disconnect-30s"], "completed": 3, "state_divergences": 0},
        "real_product_benchmark": {
            "product_id": "OPA", "version": "1.19.0", "artifact_sha256": candidate["comparator"]["artifact_sha256"],
            "corpus_sha256": sha(b"synthetic-corpus"), "host_fingerprint_sha256": sha(b"synthetic-host"),
            "toolchain_sha256": sha(b"synthetic-toolchain"), "candidate_safety_failures": 0,
            "comparator_safety_failures": 0,
        },
    }
    candidate_trials = [760 + ((i * 37) % 80) for i in range(30)]
    comparator_trials = [980 + ((i * 53) % 100) for i in range(30)]
    bench = metrics["real_product_benchmark"]
    cp95 = sorted(candidate_trials)[(95 * len(candidate_trials) + 99) // 100 - 1]
    op95 = sorted(comparator_trials)[(95 * len(comparator_trials) + 99) // 100 - 1]
    improvement = ((op95 - cp95) * 10000) // op95
    seed = sha(canon({"method": "paired-bootstrap-p95-bp-v1", "candidate_trials_sha256": sha(canon(candidate_trials)),
                      "comparator_trials_sha256": sha(canon(comparator_trials))}))
    ci_low, ci_high = kernel.bootstrap_ci(candidate_trials, comparator_trials, seed_sha256=seed)
    bench.update({"candidate_trials": candidate_trials, "comparator_trials": comparator_trials,
                  "candidate_trials_sha256": sha(canon(candidate_trials)), "comparator_trials_sha256": sha(canon(comparator_trials)),
                  "candidate_p95_us": cp95, "comparator_p95_us": op95, "improvement_basis_points": improvement,
                  "confidence_interval_method": "paired-bootstrap-p95-bp-v1", "confidence_interval_resamples": 4096,
                  "confidence_level_basis_points": 9500, "confidence_interval_seed_sha256": seed,
                  "confidence_interval_low_basis_points": ci_low, "confidence_interval_high_basis_points": ci_high})
    summary_keys = ["corpus_sha256", "host_fingerprint_sha256", "toolchain_sha256", "candidate_trials_sha256",
                    "comparator_trials_sha256", "candidate_p95_us", "comparator_p95_us", "improvement_basis_points",
                    "confidence_interval_method", "confidence_interval_resamples", "confidence_level_basis_points",
                    "confidence_interval_seed_sha256", "confidence_interval_low_basis_points", "confidence_interval_high_basis_points"]
    bench["derived_summary_sha256"] = sha(canon({k: bench[k] for k in summary_keys}))
    for kind, measurement in metrics.items():
        evidence = {"schema_version": 2, "kind": kind, "initiative_id": "PGK-FAILCLOSED-001",
                    "candidate_sha256": candidate_hash, "result": "PASS", "observed_at": observed_at,
                    "measurements": measurement}
        write(root / f"evidence/{kind}.json", sign(evidence, roster["gate_issuers"][kind], private))
    for case_id in dispatch["mandatory_blind_replay"]:
        slug = case_id.lower()
        target_name, mutation_operator, invariant = kernel.BLIND_CASE_CONTRACTS[case_id]
        target_rel = kernel.SEMANTIC_TARGET_PATHS[target_name]
        original_rel = "blind-artifacts/" + slug + ".original.bin"
        original_target_bytes = (seeded_verdict_bytes if target_name == "verdict"
                                 else (root / target_rel).read_bytes())
        (root / original_rel).write_bytes(original_target_bytes)
        # Keep the whole signed envelope valid while changing a semantic field
        # unique to this case.  The production kernel must reach the named
        # semantic checkpoint; parser/signature failures are inadmissible.
        envelope = json.loads(original_target_bytes.decode("utf-8"))
        mutated_payload = copy.deepcopy(envelope["payload"])
        signer = envelope["signer_id"]
        if case_id == "PGK-V2-BLIND-KEYRECOVERY":
            # Claim the production signer/payload identity but sign with the
            # coordinator key: this mutates real signature/key material while
            # retaining the production signer label.
            mutated_bytes = canon(sign(mutated_payload, "coordinator-a", private)) + b"\n"
            forged = json.loads(mutated_bytes)
            forged["signer_id"] = "builder-a"
            mutated_bytes = canon(forged) + b"\n"
        elif case_id == "PGK-V2-BLIND-STATE-ROOT-SWAP":
            mutated_payload["authoritative_root"] = str((root / "attacker-state").absolute())
        elif case_id == "PGK-V3-BLIND-BENCH-ARITH":
            mutated_payload["measurements"]["improvement_basis_points"] = 9999
        elif case_id == "PGK-V3-BLIND-FUTURE-EVIDENCE":
            mutated_payload["observed_at"] = "9999-12-31T23:59:59Z"
        elif case_id == "PGK-V3-BLIND-ONE-MUTATION":
            # The aggregate verdict snapshot is initially empty; make the
            # hostile artifact non-identical while still proving that fewer
            # than the frozen eleven independently bound results exist.
            mutated_payload["independent_mutations"] = 1
        elif case_id == "PGK-V3-BLIND-STATE-SYMLINK":
            attacker = root / "attacker-state"; attacker.mkdir(exist_ok=True)
            junction = root / "semantic-targets/authority-junction"
            if not junction.exists():
                subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(attacker)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            mutated_payload["authoritative_root"] = str(junction.absolute())
        elif case_id == "PGK-V4-BLIND-RESULT-PIN":
            mutated_payload["recipe_artifact_sha256"] = "b" * 64
        elif case_id == "PGK-V4-BLIND-CI-ASSERTION":
            mutated_payload["measurements"]["confidence_interval_low_basis_points"] = 1000
            mutated_payload["measurements"]["confidence_interval_high_basis_points"] = 2000
        elif case_id == "PGK-V4-BLIND-STALE-WINDOW":
            mutated_payload["collection_not_after"] = (issued_at - dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        elif case_id == "PGK-V5-BLIND-FUTURE-RESULT":
            mutated_payload["observed_at"] = "9999-12-31T23:59:59Z"
        elif case_id == "PGK-V5-BLIND-ASSERTED-PROVENANCE":
            mutated_payload["declared_executed_sha256"] = "0" * 64
        if case_id != "PGK-V2-BLIND-KEYRECOVERY":
            mutated_bytes = canon(sign(mutated_payload, signer, private)) + b"\n"
        mutated_rel = "blind-artifacts/" + slug + ".mutated.bin"
        (root / mutated_rel).write_bytes(mutated_bytes)
        recipe = {
            "schema_version": 2, "kind": "blind_replay_recipe_v2", "initiative_id": "PGK-FAILCLOSED-001",
            "case_id": case_id, "candidate_sha256": candidate_hash,
            "dispatch_sha256": sha((root / "dispatch.json").read_bytes()), "reviewer_id": "reviewer-new",
            "execution_mode": "trusted-kernel-child-v21", "interpreter_sha256": interpreter_hash,
            "kernel_sha256": kernel_hash, "arguments": ["--pgk-blind-child-v21"],
            "working_directory": ".", "environment": kernel.BLIND_EXECUTION_ENVIRONMENT,
            "mutated_artifact_path": mutated_rel, "mutated_artifact_sha256": sha(mutated_bytes),
        }
        recipe_rel = "blind-recipes/" + slug + ".json"
        write(root / recipe_rel, sign(recipe, "reviewer-new", private))
        stdout_rel = "blind-io/" + slug + ".stdout"
        stderr_rel = "blind-io/" + slug + ".stderr"
        (root / stdout_rel).parent.mkdir(parents=True, exist_ok=True)
        (root / stdout_rel).write_bytes(b"DENY\n")
        # Capture the real validator-produced trace, rather than constructing
        # an asserted observation in fixture code.
        try:
            kernel.decide_semantic_case(root, {n: n + ".json" for n in ["candidate", "dispatch"]},
                                        {n: sha((root / (n + ".json")).read_bytes()) for n in ["candidate", "dispatch"]},
                                        case_id, target_rel, mutated_rel, sha(mutated_bytes),
                                        semantic_now=now)
            raise AssertionError("semantic hostile case unexpectedly accepted")
        except kernel.TypedSemanticReject as exc:
            stderr_bytes = kernel.SEMANTIC_REJECTION_PREFIX + canon(exc.trace) + b"\n"
        (root / stderr_rel).write_bytes(stderr_bytes)
        replay = {
            "schema_version": 1, "kind": "blind_replay_v1", "initiative_id": "PGK-FAILCLOSED-001",
            "case_id": case_id, "candidate_sha256": candidate_hash,
            "dispatch_sha256": sha((root / "dispatch.json").read_bytes()), "reviewer_id": "reviewer-new",
            "result": "DENY", "executed_at": observed_at, "exit_code": 2,
            "recipe_artifact_path": recipe_rel, "recipe_artifact_sha256": sha((root / recipe_rel).read_bytes()),
            "stdout_artifact_path": stdout_rel, "stdout_artifact_sha256": sha(b"DENY\n"),
            "stderr_artifact_path": stderr_rel, "stderr_artifact_sha256": sha(stderr_bytes),
        }
        replay_rel = "blind-replays/" + case_id.lower() + ".json"
        write(root / replay_rel, sign(replay, "reviewer-new", private))
        replay_hash = sha((root / replay_rel).read_bytes())
        mutation = {
            "schema_version": 1, "kind": "blind_mutation_v1", "initiative_id": "PGK-FAILCLOSED-001",
            "case_id": case_id, "candidate_sha256": candidate_hash,
            "dispatch_sha256": sha((root / "dispatch.json").read_bytes()), "reviewer_id": "reviewer-new",
            "mutation_type": mutation_operator, "target_path": target_rel,
            "original_artifact_path": original_rel, "original_artifact_sha256": sha((root / original_rel).read_bytes()),
            "mutated_artifact_path": mutated_rel, "mutated_artifact_sha256": sha(mutated_bytes),
            "recipe_artifact_path": recipe_rel, "recipe_artifact_sha256": sha((root / recipe_rel).read_bytes()),
            "replay_artifact_sha256": replay_hash,
        }
        mutation_rel = "blind-mutations/" + case_id.lower() + ".json"
        write(root / mutation_rel, sign(mutation, "reviewer-new", private))
        blind = {
            "schema_version": 1, "initiative_id": "PGK-FAILCLOSED-001", "case_id": case_id,
            "candidate_sha256": candidate_hash, "dispatch_sha256": sha((root / "dispatch.json").read_bytes()),
            "reviewer_id": "reviewer-new", "result": "DENY", "observed_at": observed_at,
            "mutation_artifact_path": mutation_rel,
            "mutation_artifact_sha256": sha((root / mutation_rel).read_bytes()),
            "replay_artifact_path": replay_rel,
            "replay_artifact_sha256": replay_hash,
        }
        rel = "blind-results/" + case_id.lower() + ".json"
        write(root / rel, sign(blind, "reviewer-new", private))
        verdict["blind_case_results"].append({"case_id": case_id, "result": "DENY", "evidence_path": rel,
                                                "evidence_sha256": sha((root / rel).read_bytes())})
    write(root / "verdict.json", sign(verdict, "reviewer-new", private))
    refs = {}
    for kind, measurement in metrics.items():
        rel = f"evidence/{kind}.json"
        refs[kind] = {"path": rel, "sha256": sha((root / rel).read_bytes())}
    gates = {
        "schema_version": 2, "initiative_id": "PGK-FAILCLOSED-001", "submission_id": "sub-009",
        "candidate_sha256": candidate_hash, "verdict_sha256": sha((root / "verdict.json").read_bytes()),
        "evidence_sealed": True, "statuses": {k: "PASS" for k in metrics}, "evidence": refs,
    }
    write(root / "gates.json", sign(gates, "coordinator-a", private))
    return {"candidate": candidate, "roster": roster, "dispatch": dispatch, "verdict": verdict, "gates": gates}


def files_and_pins(root):
    names = ["candidate", "dispatch", "roster", "verdict", "gates"]
    return ({name: name + ".json" for name in names},
            {name: sha((root / (name + ".json")).read_bytes()) for name in names})

