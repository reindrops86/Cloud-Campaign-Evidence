from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol

from app.models import EvidenceRecord

# LookupEvents only returns management and Insights events; S3/Lambda data events
# require a trail export or CloudTrail Lake.
DATA_EVENT_SOURCES = {"s3.amazonaws.com", "lambda.amazonaws.com", "dynamodb.amazonaws.com"}


class EvidenceSource(Protocol):
    """Common interface so file-based and live AWS collection are interchangeable."""

    def events_for_access_key(
        self,
        access_key_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> List[EvidenceRecord]: ...


def _classify_event(event_source: str, read_only: Optional[bool], management_event: Optional[bool]) -> str:
    if management_event is False:
        return "Data"
    if management_event is True:
        return "Management"
    if event_source in DATA_EVENT_SOURCES and read_only is not None:
        return "Data"
    return "Management"


def _normalize(
    raw_event: Dict[str, Any],
    *,
    provider_source: str,
    region: Optional[str],
    event_id: Optional[str] = None,
    resources: Optional[List[Dict[str, Any]]] = None,
) -> EvidenceRecord:
    identity = raw_event.get("userIdentity", {}) or {}
    resolved_id = event_id or raw_event.get("eventID") or ""
    return EvidenceRecord(
        evidence_id=f"cloudtrail-{resolved_id}",
        provider="aws",
        source=provider_source,
        event_id=resolved_id,
        event_time=raw_event.get("eventTime", ""),
        account_id=raw_event.get("recipientAccountId") or identity.get("accountId"),
        region=raw_event.get("awsRegion") or region,
        principal_arn=identity.get("arn"),
        access_key_id=identity.get("accessKeyId"),
        source_ip=raw_event.get("sourceIPAddress"),
        event_source=raw_event.get("eventSource", ""),
        event_name=raw_event.get("eventName", ""),
        event_category=_classify_event(
            raw_event.get("eventSource", ""),
            raw_event.get("readOnly"),
            raw_event.get("managementEvent"),
        ),
        resources=resources if resources is not None else (raw_event.get("resources") or []),
        raw_event=raw_event,
    )


def _within_window(record: EvidenceRecord, start_time: datetime, end_time: datetime) -> bool:
    if not record.event_time:
        return True
    try:
        stamp = datetime.fromisoformat(record.event_time.replace("Z", "+00:00"))
    except ValueError:
        return True
    return start_time <= stamp <= end_time


class FileCloudTrailSource:
    """Reads exported CloudTrail JSON so investigations run without an AWS account."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _load_raw_events(self) -> Iterable[Dict[str, Any]]:
        payload = json.loads(self.path.read_text(encoding="utf-8"))

        if isinstance(payload, dict) and "Records" in payload:
            return payload["Records"]
        if isinstance(payload, dict) and "Events" in payload:
            events = []
            for summary in payload["Events"]:
                raw = summary.get("CloudTrailEvent")
                events.append(json.loads(raw) if isinstance(raw, str) else summary)
            return events
        if isinstance(payload, list):
            return payload
        return []

    def events_for_access_key(
        self,
        access_key_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        for raw in self._load_raw_events():
            record = _normalize(raw, provider_source="cloudtrail_file_export", region=None)
            if record.access_key_id != access_key_id:
                continue
            if not _within_window(record, start_time, end_time):
                continue
            records.append(record)
        return records


class LiveCloudTrailSource:
    """Queries CloudTrail LookupEvents using the standard AWS credential chain."""

    def __init__(self, profile_name: Optional[str] = None, region: str = "us-east-1") -> None:
        import boto3  # imported lazily so offline mode needs no AWS SDK

        session = boto3.Session(profile_name=profile_name) if profile_name else boto3.Session()
        self.client = session.client("cloudtrail", region_name=region)
        self.region = region

    def events_for_access_key(
        self,
        access_key_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> List[EvidenceRecord]:
        paginator = self.client.get_paginator("lookup_events")
        records: List[EvidenceRecord] = []

        for page in paginator.paginate(
            LookupAttributes=[{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}],
            StartTime=start_time,
            EndTime=end_time,
        ):
            for summary in page.get("Events", []):
                raw_event = json.loads(summary["CloudTrailEvent"])
                records.append(
                    _normalize(
                        raw_event,
                        provider_source="cloudtrail_lookup_events",
                        region=self.region,
                        event_id=summary.get("EventId"),
                        resources=summary.get("Resources", []),
                    )
                )

        return records


def build_source(
    mode: str,
    *,
    file_path: Optional[str] = None,
    profile_name: Optional[str] = None,
    region: str = "us-east-1",
) -> EvidenceSource:
    if mode == "aws":
        return LiveCloudTrailSource(profile_name=profile_name, region=region)
    if not file_path:
        raise ValueError("file source requires file_path")
    return FileCloudTrailSource(file_path)
