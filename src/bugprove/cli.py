import asyncio
import functools
import json
import os
from datetime import datetime
from enum import Enum, unique
from typing import List, Tuple

import click
import tqdm

from .client import BugProveClient, ScanIndirectUploadRequest, UploadProgress
from .internal import ComponentCategory, CvssVector, ScanConfiguration, ScanResponse, UploadType
from .internal.models.known_vulnerability_filter import KnownVulnerabilityFilter


class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()
        return json.JSONEncoder.default(self, o)


def async_entry_point(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


def global_params(func):
    @click.option(
        "--json",
        "is_json",
        is_flag=True,
        help="Print raw JSON responses",
    )
    @click.option(
        "--hostname",
        "hostname",
        help="Override the hostname used when making requests to BugProve",
        metavar="HOST",
    )
    @click.option(
        "--insecure",
        "insecure",
        is_flag=True,
        default=False,
        help="Do not validate server certificates when making HTTPS requests",
    )
    @click.option(
        "--wait",
        "wait",
        is_flag=True,
        default=False,
        help="Wait for the scan to finish",
    )
    @click.option(
        "--wait-for-subscans",
        "wait_for_subscans",
        is_flag=True,
        default=False,
        help="Wait for subscans to finish (implies --wait)",
    )
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


class CatchExceptions(click.Group):
    def __call__(self, *args, **kwargs):
        try:
            return self.main(*args, **kwargs)
        except Exception as ex:
            click.echo(ex, err=True)


@click.group(cls=CatchExceptions)
@click.version_option("1.0.0")
def main():
    pass


def format_response(is_json: bool, response: ScanResponse):
    if is_json:
        click.echo(json.dumps(response.to_dict(), cls=DateTimeEncoder, indent=4))
    else:
        click.echo(response.status)


async def get_scan(ctx: BugProveClient, scan_id: str, wait: bool, is_json: bool, wait_for_subscans: bool):
    if wait or wait_for_subscans:
        response = await ctx.wait_for_scan(scan_id, wait_for_subscans=wait_for_subscans)
    else:
        response = await ctx.scans.get_scan(scan_id)
    return format_response(is_json, response)


@main.command("status", help="Check the status of a scan", no_args_is_help=True)
@global_params
@click.argument("scan_id")
@async_entry_point
async def cli_get_scan(
    scan_id: str, wait: bool, is_json: bool, hostname: str | None, insecure: bool, wait_for_subscans: bool
):
    async with BugProveClient(hostname=hostname, insecure=insecure) as context:
        await get_scan(context, scan_id, wait, is_json, wait_for_subscans)


@unique
class PrisScanType(str, Enum):
    AUTO = "auto"
    MANUAL = "manual"
    CUSTOM = "custom"

    def __str__(self) -> str:
        return str(self.value)


@unique
class MonitoringType(str, Enum):
    ON = "on"
    OFF = "off"

    def __str__(self) -> str:
        return str(self.value)


def parse_known_vulns(known_vulns: List[str] | None) -> KnownVulnerabilityFilter | None:
    def try_get_float(x):
        try:
            return float(x)
        except ValueError:
            return None

    if known_vulns is None:
        return None
    if "all" in known_vulns:
        return KnownVulnerabilityFilter(minimumCvssScore=11)
    vuln_filter = KnownVulnerabilityFilter()
    for v in [x.capitalize() if isinstance(x, str) else x for x in known_vulns]:
        try:
            is_local = v == CvssVector.LOCAL
            if is_local or v == CvssVector.PHYSICAL:
                if not vuln_filter.ignored_cvss_vectors:
                    vuln_filter.ignored_cvss_vectors = []
                if is_local:
                    vuln_filter.ignored_cvss_vectors.append(CvssVector.LOCAL)
                else:
                    vuln_filter.ignored_cvss_vectors.append(CvssVector.PHYSICAL)
            elif v == ComponentCategory.KERNEL:
                vuln_filter.ignored_dependency_categories = [ComponentCategory.KERNEL]
            elif (num := try_get_float(v)) is not None:
                parsed = max(0, min(int(num * 10), 100)) / 10
                vuln_filter.minimum_cvss_score = parsed
            else:
                raise click.BadParameter(f"Invalid parameter: {v}", param=None)
        except Exception as ex:
            raise click.BadParameter(f"Unexpected error while parsing parameter: {v}") from ex
    return vuln_filter


def peek_upload_type(input_path: str) -> UploadType:
    with open(input_path, "rb") as input_stream:
        magic = input_stream.read(4)
        if magic == b"\x7fELF":
            return UploadType.BINARY
        else:
            return UploadType.FIRMWARE


def parse_binary_scan(no_binary_scans: bool | None, binaries: List[str]) -> Tuple[bool, List[str] | None]:
    if len(binaries) > 5:
        raise click.BadParameter("Too many binaries specified (limit: 5)")
    if no_binary_scans and len(binaries) > 0:
        raise click.BadParameter("--no-binary-scans and --binary cannot be used together")
    if no_binary_scans:
        # disable pris scans
        return (True, None)
    if binaries:
        # manual with specific binaries
        return (True, binaries)
    # automatic binary pick
    return (False, None)


@main.command("scan", help="Upload and scan an artifact", no_args_is_help=True)
@click.argument(
    "input_path",
    type=click.Path(exists=True, dir_okay=False, file_okay=True),
    metavar="PATH",
)
@click.option(
    "--name",
    "name",
    help="Display name of the scan (defaults to file name)",
    metavar="NAME",
)
@click.option(
    "--as-firmware",
    "as_firmware",
    is_flag=True,
    default=False,
    help="Start a firmware scan even if the file is an ELF binary",
)
@click.option(
    "--family-id",
    "family_id",
    help="Associate scan with a product or project",
    metavar="FAMILY_ID",
)
@click.option(
    "--monitor",
    "monitoring_enabled",
    is_flag=True,
    default=False,
    help="Enable vulnerability monitoring",
)
@click.option(
    "--ignore",
    "known_vulns",
    multiple=True,
    default=[],
    help="Ignore some known vulnerabilities",
    metavar="all|local|physical|kernel|<MIN_CVSS_SCORE>",
)
@click.option(
    "--binary",
    multiple=True,
    default=[],
    help="Start a subscan for a named binary extracted from the firmware",
    metavar="NAME",
)
@click.option(
    "--no-binary-scans",
    "no_binary_scans",
    is_flag=True,
    help="Do not automatically start subscans for the most likely to be vulnerable binaries",
)
@global_params
@async_entry_point
async def cli_upload_scan(
    input_path: str,
    as_firmware: bool,
    name: str | None,
    family_id: str | None,
    monitoring_enabled: bool,
    known_vulns: List[str] | None,
    no_binary_scans: bool | None,
    binary: List[str],
    is_json: bool,
    wait: bool,
    hostname: str | None,
    insecure: bool,
    wait_for_subscans: bool,
):
    upload_type = peek_upload_type(input_path) if not as_firmware else UploadType.FIRMWARE
    if upload_type == UploadType.FIRMWARE:
        (is_manual, binaries) = parse_binary_scan(no_binary_scans, binary)
        configuration = ScanConfiguration(
            isManual=is_manual,
            binariesToScan=binaries,
            isDebugBuild=None,
            knownVulnerabilityFilter=parse_known_vulns(known_vulns),
            monitoringEnabled=monitoring_enabled,
        )
    else:
        configuration = None
    request = ScanIndirectUploadRequest(
        name=name or os.path.basename(input_path),
        upload_type=upload_type,
        family_id=family_id,
        configuration=configuration,
    )
    progress = tqdm.tqdm(total=0, unit_scale=True, unit="B", disable=is_json, gui=False)

    def print_progress(state: UploadProgress, values: Tuple[int, int] | None):
        if is_json:
            return

        label_map = {
            UploadProgress.CHECKSUM: "Calculating checksums",
            UploadProgress.UPLOAD_START: "Uploading",
            UploadProgress.UPLOAD_END: "Starting scan",
            UploadProgress.CANCEL: "Cancelling upload",
            UploadProgress.FINALIZE: "Scan started",
        }

        if state == UploadProgress.UPLOAD_CHANGE:
            if values is not None:
                progress.update(values[0])
        else:
            if state == UploadProgress.UPLOAD_START:
                progress.__enter__()
                if values is not None:
                    progress.total = values[1]
            elif state == UploadProgress.UPLOAD_END:
                progress.__exit__(None, None, None)
            progress.write(f"> {label_map[state]}")

    async with BugProveClient(hostname=hostname, insecure=insecure) as context:
        with open(input_path, "rb") as input_stream:
            response = await context.upload_and_scan(input_stream, request, print_progress)
        await get_scan(context, response.id, wait, is_json, wait_for_subscans)
