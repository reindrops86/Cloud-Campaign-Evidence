from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from app.models import EvidenceRecord, K8sSubject, WorkloadIdentity

# RBAC verbs that let a subject reach credentials it was not directly granted.
POD_CREATE_VERBS = {"create", "*"}
ESCALATION_VERBS = {"escalate", "bind", "impersonate"}
EXEC_RESOURCES = {"pods/exec", "pods/attach", "pods/portforward"}
SECRET_RESOURCES = {"secrets"}


def _matches(values: List[str], target: str) -> bool:
    return "*" in values or target in values


class K8sRBACSource:
    """Loads a Kubernetes RBAC + workload snapshot and resolves effective subjects.

    Works from an exported snapshot so the analysis is reproducible without
    cluster credentials.
    """

    def __init__(self, path: str | Path) -> None:
        self.snapshot: Dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))
        self.cluster_name: str = self.snapshot.get("cluster_name", "unknown-cluster")
        self._roles = self._index_roles()

    def _index_roles(self) -> Dict[str, Dict[str, Any]]:
        index: Dict[str, Dict[str, Any]] = {}
        for role in self.snapshot.get("roles", []):
            index[f"Role/{role.get('namespace', '')}/{role['name']}"] = role
        for role in self.snapshot.get("cluster_roles", []):
            index[f"ClusterRole//{role['name']}"] = role
        return index

    def _rules_for_binding(self, binding: Dict[str, Any]) -> List[Dict[str, Any]]:
        ref = binding.get("roleRef", {})
        kind = ref.get("kind", "Role")
        namespace = binding.get("namespace", "") if kind == "Role" else ""
        role = self._roles.get(f"{kind}/{namespace}/{ref.get('name')}")
        return role.get("rules", []) if role else []

    def subjects(self) -> List[K8sSubject]:
        """Collapse every binding into per-subject effective verbs."""
        collected: Dict[str, K8sSubject] = {}

        bindings = self.snapshot.get("role_bindings", []) + self.snapshot.get(
            "cluster_role_bindings", []
        )

        for binding in bindings:
            rules = self._rules_for_binding(binding)

            for subj in binding.get("subjects", []):
                key = f"{subj['kind']}/{subj.get('namespace', '')}/{subj['name']}"
                subject = collected.setdefault(
                    key,
                    K8sSubject(
                        name=subj["name"],
                        kind=subj["kind"],
                        namespace=subj.get("namespace"),
                    ),
                )
                subject.binding_names.append(binding["name"])

                for rule in rules:
                    for resource in rule.get("resources", []):
                        verbs = subject.verbs_by_resource.setdefault(resource, [])
                        for verb in rule.get("verbs", []):
                            if verb not in verbs:
                                verbs.append(verb)

        return list(collected.values())

    def service_accounts(self) -> List[WorkloadIdentity]:
        """ServiceAccounts as federated workload identities."""
        workloads: List[WorkloadIdentity] = []
        for sa in self.snapshot.get("service_accounts", []):
            namespace = sa.get("namespace", "default")
            name = sa["name"]
            annotations = sa.get("annotations", {})
            workloads.append(
                WorkloadIdentity(
                    workload_id=f"k8s::{namespace}/{name}",
                    plane="kubernetes",
                    subject=f"system:serviceaccount:{namespace}:{name}",
                    display_name=f"{namespace}/{name}",
                    namespace=namespace,
                    metadata={
                        "cluster": self.cluster_name,
                        # IRSA advertises the target role on the ServiceAccount itself.
                        "annotated_role_arn": annotations.get(
                            "eks.amazonaws.com/role-arn"
                        ),
                        "automount_token": sa.get("automountServiceAccountToken", True),
                    },
                )
            )
        return workloads

    def pods_using(self, service_account: str, namespace: str) -> List[Dict[str, Any]]:
        return [
            pod
            for pod in self.snapshot.get("pods", [])
            if pod.get("serviceAccountName") == service_account
            and pod.get("namespace") == namespace
        ]

    def subjects_who_can_use(self, workload: WorkloadIdentity) -> List[Tuple[K8sSubject, str]]:
        """Find RBAC subjects that can obtain a ServiceAccount's token.

        Three distinct routes, each reported with the verb that enables it, so an
        analyst can tell a pod-create pivot from a direct secret read.
        """
        routes: List[Tuple[K8sSubject, str]] = []

        for subject in self.subjects():
            # A subject scoped to another namespace cannot reach this ServiceAccount.
            if subject.namespace and subject.namespace != workload.namespace:
                continue

            pod_verbs = subject.verbs_by_resource.get("pods", [])
            if POD_CREATE_VERBS & set(pod_verbs):
                routes.append(
                    (
                        subject,
                        "create pods with serviceAccountName: mounts the SA token into "
                        "an attacker-controlled pod",
                    )
                )

            for resource in EXEC_RESOURCES:
                if subject.verbs_by_resource.get(resource):
                    routes.append(
                        (subject, f"{resource}: executes inside an existing pod already "
                                  f"running as the ServiceAccount")
                    )
                    break

            secret_verbs = subject.verbs_by_resource.get("secrets", [])
            if {"get", "list", "*"} & set(secret_verbs):
                routes.append(
                    (subject, "get/list secrets: reads the ServiceAccount token directly")
                )

            token_verbs = subject.verbs_by_resource.get("serviceaccounts/token", [])
            if POD_CREATE_VERBS & set(token_verbs):
                routes.append(
                    (subject, "create serviceaccounts/token: mints a token via the "
                              "TokenRequest API")
                )

            for verb_set in subject.verbs_by_resource.values():
                if ESCALATION_VERBS & set(verb_set):
                    routes.append(
                        (subject, "escalate/bind/impersonate: grants itself the rights "
                                  "needed to reach the ServiceAccount")
                    )
                    break

        return routes


def load_audit_events(path: str | Path) -> List[EvidenceRecord]:
    """Normalize a Kubernetes audit log export into EvidenceRecords."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    items = payload.get("items", payload) if isinstance(payload, dict) else payload

    records: List[EvidenceRecord] = []
    for item in items:
        user = item.get("user", {}) or {}
        obj = item.get("objectRef", {}) or {}
        records.append(
            EvidenceRecord(
                evidence_id=f"k8saudit-{item.get('auditID', '')}",
                provider="kubernetes",
                source="k8s_audit_log",
                event_id=item.get("auditID", ""),
                event_time=item.get("requestReceivedTimestamp", ""),
                account_id=None,
                region=None,
                principal_arn=user.get("username"),
                access_key_id=None,
                source_ip=(item.get("sourceIPs") or [None])[0],
                event_source="kubernetes.audit",
                event_name=f"{item.get('verb', '')} {obj.get('resource', '')}".strip(),
                event_category="Management",
                resources=[
                    {
                        "ARN": f"{obj.get('namespace', '')}/{obj.get('resource', '')}/{obj.get('name', '')}",
                        "type": obj.get("resource", ""),
                    }
                ],
                raw_event=item,
            )
        )
    return records


def observed_pod_creates(records: List[EvidenceRecord]) -> Dict[str, List[str]]:
    """Map `namespace/serviceAccountName` to the audit events that prove a pod ran as it."""
    observed: Dict[str, List[str]] = {}
    for record in records:
        raw = record.raw_event
        if raw.get("verb") != "create":
            continue
        if (raw.get("objectRef", {}) or {}).get("resource") != "pods":
            continue

        spec = ((raw.get("requestObject", {}) or {}).get("spec", {}) or {})
        sa_name = spec.get("serviceAccountName")
        namespace = (raw.get("objectRef", {}) or {}).get("namespace", "default")
        if sa_name:
            observed.setdefault(f"{namespace}/{sa_name}", []).append(record.evidence_id)

    return observed
