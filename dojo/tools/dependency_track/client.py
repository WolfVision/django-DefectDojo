from urllib.parse import urlsplit
from uuid import UUID

import requests


class DependencyTrackSyncError(ValueError):
    pass


def fetch_project_findings(base_url, api_key, project_uuid, *, page_size=500):
    if not isinstance(base_url, str):
        message = "Invalid Dependency-Track API URL"
        raise DependencyTrackSyncError(message)
    parsed_url = urlsplit(base_url)
    if (
        parsed_url.scheme not in {"http", "https"}
        or not parsed_url.hostname
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.query
        or parsed_url.fragment
    ):
        message = "Invalid Dependency-Track API URL"
        raise DependencyTrackSyncError(message)
    if not isinstance(api_key, str) or not api_key.strip() or not isinstance(page_size, int) or isinstance(page_size, bool) or page_size < 1:
        message = "Invalid Dependency-Track API configuration"
        raise DependencyTrackSyncError(message)

    project = str(UUID(str(project_uuid)))
    url = f"{base_url.rstrip('/')}/api/v1/finding/project/{project}"
    findings = []
    matrices = set()
    expected_total = None
    page_number = 1

    while True:
        try:
            response = requests.get(
                url,
                headers={"X-Api-Key": api_key},
                params={"suppressed": "true", "pageNumber": page_number, "pageSize": page_size},
                timeout=(5, 30),
                allow_redirects=False,
            )
            if response.status_code != 200:
                message = f"Dependency-Track snapshot request failed with HTTP {response.status_code}"
                raise DependencyTrackSyncError(message)
            count = int(response.headers["X-Total-Count"])
            count_type = response.headers.get("X-Total-Count-Type")
            if count_type and count_type.upper() != "EXACT":
                message = "Dependency-Track snapshot count is not exact"
                raise DependencyTrackSyncError(message)
            page = response.json()
        except (requests.RequestException, KeyError, TypeError) as error:
            message = "Unable to retrieve a complete Dependency-Track snapshot"
            raise DependencyTrackSyncError(message) from error

        if count < 0 or not isinstance(page, list) or len(page) > page_size:
            message = "Invalid Dependency-Track snapshot page"
            raise DependencyTrackSyncError(message)
        if expected_total is None:
            expected_total = count
        elif count != expected_total:
            message = "Dependency-Track snapshot changed during pagination"
            raise DependencyTrackSyncError(message)

        for finding in page:
            if not isinstance(finding, dict) or not isinstance(finding.get("matrix"), str):
                message = "Dependency-Track snapshot contains a finding without an identity"
                raise DependencyTrackSyncError(message)
            matrix = finding["matrix"]
            parts = matrix.split(":")
            try:
                canonical = ":".join(str(UUID(part)) for part in parts) if len(parts) == 3 else None
                valid_identity = canonical == matrix and parts[0] == project
            except ValueError:
                valid_identity = False
            if not valid_identity or matrix in matrices:
                message = "Dependency-Track snapshot contains an invalid or repeated identity"
                raise DependencyTrackSyncError(message)
            matrices.add(matrix)
            findings.append(finding)

        if len(findings) == expected_total:
            return findings
        if not page or len(findings) > expected_total:
            message = "Incomplete Dependency-Track snapshot"
            raise DependencyTrackSyncError(message)
        page_number += 1
