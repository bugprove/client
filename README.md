# BugProve API client

## About

BugProve is an automated firmware analysis platform to identify known and zero-day vulnerabilities and to support your compliance needs. As of now, this package contains a CLI interface and a library to call all actions supported by the BugProve public API.

## How to install?

You can install `bugprove` with pip or another Python package manager of your choice:

```bash
pip install bugprove
```

## Getting started

### CLI

You can use the package directly from the command line to start new scans and wait for scans to finish, facilitating integration with CI/CD pipelines. A valid BugProve API key is required to be set using the `BUGPROVE_API_KEY` environment variable before commands can be issued.

For example, to start a new scan for the `firmware.bin` file in the current directory, simply run:

```bash
bugprove scan firmware.bin
```

Check out `bugprove scan --help` to see the list of options available.

### Library

If you wish to interact with other parts of BugProve's public API, you can use the package as a Python library in your own scripts. The library has both high-level and low-level primitives to support interacting with the API. 

```python
from io import open
from pathlib import Path

from bugprove.client import BugProveClient, ScanIndirectUploadRequest
from bugprove.internal.models.upload_type import UploadType


async def upload_and_generate_report(input_path: Path, output_path: Path):
    async with BugProveClient() as ctx:
        # Upload a file to scan
        with open(input_path, mode="rb") as input_stream:
            request = ScanIndirectUploadRequest(name="Firmware", upload_type=UploadType.FIRMWARE)
            scan = await ctx.upload_and_scan(input_stream, request)
        await ctx.wait_for_scan(scan.id)

        # List findings
        findings = await ctx.scans.list_findings(scan.id)
        for finding in findings:
            print(f"[{finding.digest}] {finding.short_description}")

        # Generate PDF report
        report = await ctx.reports.create_report(scan.id)
        await ctx.wait_for_report(scan.id, report.revision)
        download = await ctx.reports.download_report(scan.id, report.revision)
        with open(output_path, mode="wb") as output_stream:
            await ctx.download_file(download, output_stream)
```

In this example code, the API client will try to obtain an API key from the `BUGPROVE_API_KEY` environment variable. You can also specify the API key explicitly when constructing the client:

```python
    async with BugProveClient(api_key="<API key>") as ctx:
```