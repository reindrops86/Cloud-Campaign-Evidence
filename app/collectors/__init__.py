from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.collectors.aws_cloudtrail import (
        EvidenceSource,
        FileCloudTrailSource,
        LiveCloudTrailSource,
    )
    from app.collectors.aws_identity import AWSIdentityCollector

__all__ = [
    "EvidenceSource",
    "FileCloudTrailSource",
    "LiveCloudTrailSource",
    "AWSIdentityCollector",
]
