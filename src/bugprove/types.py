from enum import Enum, unique
from typing import Optional

import attr
from bugprove.internal.models.start_scan_with_indirect_upload_request import StartScanWithIndirectUploadRequest
from bugprove.internal.models.upload import Upload

from .internal.models.scan_configuration import ScanConfiguration
from .internal.models.upload_type import UploadType


class BugProveException(Exception):
    """Base exception class for all exceptions"""


@unique
class UploadProgress(int, Enum):
    BEGIN = 0
    CHECKSUM = 1
    UPLOAD_START = 2
    UPLOAD_CHANGE = 3
    UPLOAD_END = 4
    CANCEL = 5
    FINALIZE = 6


@attr.define(kw_only=True, frozen=True)
class ScanIndirectUploadRequest:
    name: str
    upload_type: UploadType
    family_id: Optional[str] = None
    configuration: Optional[ScanConfiguration] = None

    def to_start_request(self, upload: Upload):
        return StartScanWithIndirectUploadRequest(
            name=self.name,
            uploadType=self.upload_type,
            familyId=self.family_id,
            upload=upload,
            configuration=self.configuration,
        )

    def dict(self):
        return {
            "name": self.name,
            "upload_type": self.upload_type,
            "family_id": self.family_id,
            "configuration": self.configuration.model_dump() if self.configuration else None,
        }
