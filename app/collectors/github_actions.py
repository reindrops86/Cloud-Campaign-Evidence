from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.models import WorkloadIdentity

# Triggers that run with repository context but are reachable by untrusted contributors.
UNTRUSTED_TRIGGERS = {"pull_request_target", "workflow_run", "issue_comment"}


class GitHubActionsSource:
    """Reads a repository/workflow snapshot and derives OIDC subject claims.

    The subject format GitHub mints is what the IAM trust policy matches against,
    so it is reconstructed here exactly rather than approximated.
    """

    def __init__(self, path: str | Path) -> None:
        self.snapshot: Dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))
        self.organization: str = self.snapshot.get("organization", "unknown-org")

    def workloads(self) -> List[WorkloadIdentity]:
        workloads: List[WorkloadIdentity] = []

        for repo in self.snapshot.get("repositories", []):
            repo_full = repo["full_name"]
            protection = repo.get("branch_protection", {})

            for workflow in repo.get("workflows", []):
                triggers = workflow.get("on", [])
                environment = workflow.get("environment")
                ref = workflow.get("ref", "refs/heads/main")

                # GitHub scopes the subject to the environment when one is used.
                if environment:
                    subject = f"repo:{repo_full}:environment:{environment}"
                elif "pull_request" in triggers or "pull_request_target" in triggers:
                    subject = f"repo:{repo_full}:pull_request"
                else:
                    subject = f"repo:{repo_full}:ref:{ref}"

                untrusted = sorted(set(triggers) & UNTRUSTED_TRIGGERS)
                unpinned = [
                    action
                    for action in workflow.get("uses", [])
                    if "@" in action and not _is_sha_pinned(action)
                ]

                workloads.append(
                    WorkloadIdentity(
                        workload_id=f"gha::{repo_full}/{workflow['name']}",
                        plane="github_actions",
                        subject=subject,
                        display_name=f"{repo_full} / {workflow['name']}",
                        metadata={
                            "repository": repo_full,
                            "private": repo.get("private", True),
                            "triggers": triggers,
                            "environment": environment,
                            "ref": ref,
                            "untrusted_triggers": untrusted,
                            "unpinned_actions": unpinned,
                            "self_hosted": workflow.get("self_hosted", False),
                            "required_reviewers": protection.get("required_reviewers", 0),
                            "environment_protected": environment
                            in repo.get("protected_environments", []),
                        },
                    )
                )

        return workloads

    def entry_conditions(self, workload: WorkloadIdentity) -> List[str]:
        """Describe how an untrusted party could cause this workflow to run."""
        meta = workload.metadata
        reasons: List[str] = []

        for trigger in meta.get("untrusted_triggers", []):
            if trigger == "pull_request_target":
                reasons.append(
                    "`pull_request_target` runs with repository secrets in the base-repo "
                    "context while checking out fork-controlled code."
                )
            elif trigger == "workflow_run":
                reasons.append(
                    "`workflow_run` executes in privileged context after a workflow that "
                    "an outside contributor can trigger."
                )
            else:
                reasons.append(f"`{trigger}` is reachable by non-maintainers.")

        if meta.get("unpinned_actions"):
            reasons.append(
                "Unpinned third-party actions ("
                + ", ".join(meta["unpinned_actions"])
                + "): a tag can be repointed to attacker-controlled code."
            )

        if meta.get("self_hosted"):
            reasons.append(
                "Self-hosted runner: job artifacts and credentials may persist between runs."
            )

        if not meta.get("private", True) and meta.get("untrusted_triggers"):
            reasons.append("Public repository: anyone can open a pull request.")

        return reasons

    def mitigations(self, workload: WorkloadIdentity) -> List[str]:
        meta = workload.metadata
        controls: List[str] = []

        if meta.get("environment_protected"):
            controls.append(
                f"Environment `{meta['environment']}` has deployment protection rules."
            )
        if meta.get("required_reviewers", 0) > 0:
            controls.append(
                f"Branch protection requires {meta['required_reviewers']} reviewer(s)."
            )
        return controls


def _is_sha_pinned(action: str) -> bool:
    ref = action.rsplit("@", 1)[-1]
    return len(ref) == 40 and all(c in "0123456789abcdef" for c in ref.lower())


def observed_web_identity_assumptions(cloudtrail_records: List[Any]) -> Dict[str, List[str]]:
    """Extract proven OIDC role assumptions from CloudTrail.

    Keyed `subject|role_arn` so a federated trust edge can be marked OBSERVED only
    when the log shows that exact workload assuming that exact role.
    """
    observed: Dict[str, List[str]] = {}

    for record in cloudtrail_records:
        if record.event_name != "AssumeRoleWithWebIdentity":
            continue

        raw = record.raw_event
        params = raw.get("requestParameters", {}) or {}
        role_arn = params.get("roleArn")

        identity = raw.get("userIdentity", {}) or {}
        subject = (
            (identity.get("sessionContext", {}) or {})
            .get("webIdFederationData", {})
            .get("attributes", {})
            .get("sub")
        ) or raw.get("additionalEventData", {}).get("sub")

        if role_arn and subject:
            observed.setdefault(f"{subject}|{role_arn}", []).append(record.evidence_id)

    return observed


def observed_role_actions(cloudtrail_records: List[Any]) -> Dict[str, Dict[str, List[str]]]:
    """Map role ARN to the actions CloudTrail shows its assumed-role sessions performing.

    Lets a federated path claim OBSERVED end to end rather than only at the
    role-assumption hop.
    """
    observed: Dict[str, Dict[str, List[str]]] = {}

    for record in cloudtrail_records:
        identity = record.raw_event.get("userIdentity", {}) or {}
        arn = identity.get("arn", "")
        if ":assumed-role/" not in arn:
            continue

        role_name = arn.split(":assumed-role/")[1].split("/")[0]
        account = arn.split(":")[4]
        role_arn = f"arn:aws:iam::{account}:role/{role_name}"

        action = f"{record.event_source.split('.')[0]}:{record.event_name}"
        observed.setdefault(role_arn, {}).setdefault(action, []).append(record.evidence_id)

    return observed
