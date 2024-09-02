import asyncio
import base64
import hashlib
import io
import os
import platform
import sys
import urllib.parse
from typing import Callable, Coroutine, List, Optional, Tuple, TypeVar

import aiohttp
import jwt

from .internal.api.families_api import FamiliesApi
from .internal.api.links_api import LinksApi
from .internal.api.reports_api import ReportsApi
from .internal.api.scans_api import ScansApi
from .internal.api.token_api import TokenApi
from .internal.api.upload_api import UploadApi
from .internal.api_client import ApiClient
from .internal.configuration import Configuration
from .internal.models.begin_indirect_upload_request import BeginIndirectUploadRequest
from .internal.models.begin_indirect_upload_response import BeginIndirectUploadResponse
from .internal.models.begin_multipart_indirect_upload_request import BeginMultipartIndirectUploadRequest
from .internal.models.begin_multipart_indirect_upload_response import BeginMultipartIndirectUploadResponse
from .internal.models.cancel_indirect_upload_request import CancelIndirectUploadRequest
from .internal.models.download_response import DownloadResponse
from .internal.models.report_generation_status import ReportGenerationStatus
from .internal.models.report_response import ReportResponse
from .internal.models.scan_response import ScanResponse
from .internal.models.scan_status import ScanStatus
from .internal.models.upload import Upload
from .internal.models.upload_type import UploadType
from .types import BugProveException, ScanIndirectUploadRequest, UploadProgress

S3_UPLOAD_TIMEOUT_SEC = 60
MINIMUM_WAIT_INTERVAL_SEC = 10
T = TypeVar("T")


class BugProveClient:
    _client: ApiClient
    _is_insecure: bool

    @property
    def families(self) -> FamiliesApi:
        return FamiliesApi(self._client)

    @property
    def scans(self) -> ScansApi:
        return ScansApi(self._client)

    @property
    def reports(self) -> ReportsApi:
        return ReportsApi(self._client)

    @property
    def links(self) -> LinksApi:
        return LinksApi(self._client)

    @property
    def tokens(self) -> TokenApi:
        return TokenApi(self._client)

    @property
    def uploads(self) -> UploadApi:
        return UploadApi(self._client)

    def __init__(self, *, api_key: str | None = None, hostname: str | None = None, insecure: bool = False) -> None:
        self._is_insecure = insecure
        api_key = api_key or os.environ.get("BUGPROVE_API_KEY")
        if not api_key:
            raise BugProveException(
                "API token 'BUGPROVE_API_KEY' must be available either as a constructor parameter "
                + "or as an environment variable"
            )
        if not hostname:
            try:
                payload = jwt.decode(api_key, options={"verify_signature": False})
                url = urllib.parse.urlparse(payload["iss"])
                if url.scheme != "https":
                    raise BugProveException("URL scheme must be 'https' in API token")
                hostname = url.hostname
            except Exception as e:
                raise BugProveException("Error during API token parse") from e
        configuration = Configuration.get_default()
        configuration.verify_ssl = not self._is_insecure
        configuration.access_token = api_key
        configuration.host = f"https://{hostname}/api/public/v1"
        self._client = ApiClient(configuration)
        (major, minor, *_) = sys.version_info
        self._client.user_agent = (
            f"BugProveClient/1.0.0 (Python {major}.{minor}; {platform.system()} {platform.version()})"
        )

    async def _upload_and_scan(
        self,
        file_stream: io.IOBase,
        request: ScanIndirectUploadRequest,
        progress_callback: Callable[[UploadProgress, Tuple[int, int] | None], None] | None = None,
    ) -> ScanResponse:
        progress_callback = progress_callback if progress_callback is not None else lambda x, y=None: None
        file_size = os.fstat(file_stream.fileno()).st_size
        hash_algo = hashlib.sha256()
        checksum: str

        def generate_checksum():
            nonlocal checksum
            progress_callback(UploadProgress.CHECKSUM, None)
            while buffer := file_stream.read(64 * 1024):
                hash_algo.update(buffer)
            checksum = base64.b64encode(hash_algo.digest()).decode()
            return checksum

        # Get signed url
        start_response: BeginMultipartIndirectUploadResponse | BeginIndirectUploadResponse
        start_request: Optional[BeginIndirectUploadRequest] = None
        e_tags: List[str] = []
        _1GB = 1024**3
        _5GB = 5 * _1GB
        if request.upload_type == UploadType.BINARY:
            is_multipart = False
            if file_size >= _5GB:
                raise BugProveException("Binary files cannot be larger than 5 GiB")
            start_request = BeginIndirectUploadRequest(size=file_size, checksum=generate_checksum())
            start_response = await self.uploads.begin_indirect_upload(start_request)
        elif request.upload_type == UploadType.FIRMWARE:
            is_multipart = file_size >= _1GB
            if is_multipart:
                start_response = await self.uploads.begin_multipart_indirect_upload(
                    BeginMultipartIndirectUploadRequest(size=file_size)
                )
            else:
                start_request = BeginIndirectUploadRequest(size=file_size, checksum=generate_checksum())
                start_response = await self.uploads.begin_indirect_upload(start_request)
        else:
            raise BugProveException("Invalid upload type")

        # Upload parts
        file_stream.seek(0, io.SEEK_SET)
        try:
            progress_callback(UploadProgress.UPLOAD_START, (0, file_size))
            signed_urls = (
                start_response.signed_urls
                if isinstance(start_response, BeginMultipartIndirectUploadResponse)
                else [start_response.signed_url]
            )
            size = (
                start_response.part_size
                if isinstance(start_response, BeginMultipartIndirectUploadResponse)
                else file_size
            )
            remaining_size = file_size
            for signed_url in signed_urls:
                headers = {"Content-Type": ""}
                if isinstance(start_request, BeginIndirectUploadRequest):
                    headers["x-amz-checksum-sha256"] = start_request.checksum

                async with aiohttp.ClientSession(headers=headers, conn_timeout=S3_UPLOAD_TIMEOUT_SEC) as session:

                    async def chunk_slice_of_file():
                        nonlocal checksum
                        remaining = size
                        chunk_size = 64 * 1024
                        while True:
                            sent_size = min(remaining, chunk_size)
                            chunk = await session.loop.run_in_executor(None, file_stream.read, sent_size)
                            yield chunk
                            progress_callback(UploadProgress.UPLOAD_CHANGE, (sent_size, file_size))
                            remaining = remaining - chunk_size
                            hash_algo.update(chunk)
                            if remaining <= 0:
                                break

                    async with session.request(
                        "PUT",
                        signed_url,
                        data=chunk_slice_of_file(),
                        ssl=not self._is_insecure,
                        headers={"Content-Length": str(min(size, remaining_size))},
                    ) as s3_response:
                        e_tags.append(s3_response.headers["ETag"])
                        remaining_size -= size
        except Exception:
            progress_callback(UploadProgress.CANCEL, None)
            await self.uploads.cancel_indirect_upload(
                CancelIndirectUploadRequest(scanId=start_response.scan_id, uploadId=start_response.upload_id)
            )
            raise
        progress_callback(UploadProgress.UPLOAD_END, (0, file_size))

        # Finalize checksum if it's multipart
        if is_multipart:
            checksum = base64.b64encode(hash_algo.digest()).decode()
            progress_callback(UploadProgress.CHECKSUM, None)

        # Create scan
        start_scan_request = request.to_start_request(
            Upload(id=start_response.upload_id, checksum=checksum, eTags=e_tags)
        )
        response = await self.uploads.start_scan_with_indirect_upload(start_response.scan_id, start_scan_request)
        progress_callback(UploadProgress.FINALIZE, None)
        return response

    async def upload_and_scan(
        self,
        stream_or_path: io.IOBase | str,
        request: ScanIndirectUploadRequest,
        progress_callback: Callable[[UploadProgress, Tuple[int, int] | None], None] | None = None,
    ) -> ScanResponse:
        """Simplified interface to create a scan by uploading a file.
        This function uses the indirect upload approach that is more robust
        and less likely to fail for huge files.

        :param stream_or_path: Local path to the file you want to upload or
            the IO object to stream the contents from
        :type file_path: IOBase | str
        :param request: Filled request configuration for the uploadable file
        :type request: ScanIndirectUploadRequest
        :param progress_callback: Callback that keeps track of the progress of the upload.
        Useful for creating progressbars and logs.
        :type progress_callback: Callable[[UploadProgress, Tuple[int, int]], None]
        :return: Returns informations about the created scan
        :rtype: ScanResponse
        """
        if isinstance(stream_or_path, str):
            with open(stream_or_path, mode="rb") as file_stream:
                return await self._upload_and_scan(file_stream, request, progress_callback)

        return await self._upload_and_scan(stream_or_path, request, progress_callback)

    async def _wait_for(
        self,
        check: Callable[[], Coroutine[None, None, Tuple[bool, T]]],
        wait_interval_sec: float,
        timeout_sec: Optional[float],
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> T:
        progress_callback = progress_callback if progress_callback is not None else lambda _: None

        if wait_interval_sec is not None and wait_interval_sec < MINIMUM_WAIT_INTERVAL_SEC:
            raise BugProveException("Wait interval too low")
        if timeout_sec is not None and timeout_sec <= 0:
            raise BugProveException("Timeout seconds must be a positive number")

        async def action():
            counter = 0
            while True:
                (is_truthy, entity) = await check()
                if is_truthy:
                    return entity
                progress_callback(counter)
                counter += 1
                await asyncio.sleep(wait_interval_sec)

        return await asyncio.wait_for(action(), timeout=timeout_sec)

    async def wait_for_scan(
        self,
        scan_id: str,
        progress_callback: Optional[Callable[[int], None]] = None,
        wait_interval_sec: float = 30,
        timeout_sec: Optional[float] = 3600,
        wait_for_subscans: Optional[bool] = False,
    ) -> ScanResponse:
        """Waits for the scan to be completed.

        :param scan_id: ID of the scan
        :type scan_id: str
        :param progress_callback: Callback that notifies the caller of event changes during upload.
        :type progress_callback: Optional[Callable[[int], None]]
        :param wait_interval_sec: Seconds to wait between retries. Cannot be lower than 10 seconds.
        :type wait_interval_sec: float
        :param timeout_sec: Seconds before the function throws a timeout exception. If None, never timeouts.
        :type timeout_sec: Optional[float]
        :param wait_for_subscans: Flag for whether we want to wait for subscans too or not.
        :type wait_for_subscans: Optional[bool]
        :return: Returns the report
        :rtype: ReportResponse
        """

        finished_statuses = [
            ScanStatus.FAILED,
            ScanStatus.INCOMPLETE,
            ScanStatus.SUCCESSFUL,
        ]

        if not wait_for_subscans:
            finished_statuses.append(ScanStatus.ANALYZINGSUBSCANS)

        async def check_status():
            response = await self.scans.get_scan(scan_id)
            return (response.status in finished_statuses, response)

        return await self._wait_for(check_status, wait_interval_sec, timeout_sec, progress_callback)

    async def wait_for_report(
        self,
        scan_id: str,
        revision: int,
        progress_callback: Optional[Callable[[int], None]] = None,
        wait_interval_sec: float = 30,
        timeout_sec: Optional[float] = 3600,
    ) -> ReportResponse:
        """Waits for the report to be generated until it is in a finished state.

        :param scan_id: ID of the scan
        :type scan_id: str
        :param revision: ID of the report
        :type revision: str
        :param progress_callback: Callback that notifies the caller of event changes during upload.
        :type progress_callback: Optional[Callable[[int], None]]
        :param wait_interval_sec: Seconds to wait between retries. Cannot be lower than 10 seconds.
        :type wait_interval_sec: float
        :param timeout_sec: Seconds before the function throws a timeout exception. If None, never timeouts.
        :type timeout_sec: Optional[float]
        :return: Returns the report
        :rtype: ReportResponse
        """

        finished_statuses = [
            ReportGenerationStatus.AVAILABLE,
            ReportGenerationStatus.FAILED,
        ]

        async def check_status():
            all_reports = await self.reports.list_reports(scan_id)
            report = next(r for r in all_reports if r.revision == revision)
            return (report.status in finished_statuses, report)

        return await self._wait_for(check_status, wait_interval_sec, timeout_sec, progress_callback)

    async def download_file(self, download_info: DownloadResponse, file_stream: io.IOBase):
        """Helper method to download files when the endpoint returns a 'DownloadResponse' object

        :param download_info: Response object that stores the URL for the file
        :type download_info: DownloadResponse
        :param file_stream: Writable stream of a custom file.
                           If left unfilled, a file will be created in the os temp directory.
        :type file_stream: io.RawIOBase
        :return: Returns the file path where the content was saved
        :rtype: str
        """
        async with aiohttp.ClientSession() as session:
            async with session.get(download_info.url) as response:
                file_stream.write(await response.read())

    async def __aenter__(self):
        await self._client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self._client.__aexit__(exc_type, exc_value, traceback)
