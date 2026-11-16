import json
import logging
from collections import Counter
from itertools import batched

from django.db import transaction
from django.utils.dateparse import parse_datetime
from django.utils.timezone import is_aware

from dojo.models import DojoMeta
from dojo.tools.dependency_track.client import DependencyTrackSyncError

logger = logging.getLogger(__name__)


def apply_analysis_status(finding, analysis):
    if analysis is None:
        analysis = {}
    if not isinstance(analysis, dict):
        message = "Invalid Dependency-Track analysis"
        raise DependencyTrackSyncError(message)

    state = analysis.get("state")
    suppressed = analysis.get("isSuppressed", False)
    if state is not None and not isinstance(state, str):
        message = "Invalid Dependency-Track analysis state"
        raise DependencyTrackSyncError(message)
    if state not in {None, "NOT_SET", "IN_TRIAGE", "EXPLOITABLE", "FALSE_POSITIVE", "NOT_AFFECTED", "RESOLVED"}:
        message = "Unknown Dependency-Track analysis state"
        raise DependencyTrackSyncError(message)
    if not isinstance(suppressed, bool):
        message = "Invalid Dependency-Track suppression status"
        raise DependencyTrackSyncError(message)

    finding.active = not suppressed and state not in {"FALSE_POSITIVE", "NOT_AFFECTED", "RESOLVED"}
    finding.verified = not suppressed and state == "EXPLOITABLE"
    finding.false_p = state == "FALSE_POSITIVE"
    finding.is_mitigated = state in {"FALSE_POSITIVE", "RESOLVED"}
    finding.under_defect_review = state == "IN_TRIAGE"
    finding._dependency_track_analysis = {"state": state, "isSuppressed": suppressed}


def record_source_analysis(importer, parser):
    for matrices in batched(parser.snapshot_analysis, 1000, strict=False):
        findings = importer.test.finding_set.filter(unique_id_from_tool__in=matrices).only("id", "unique_id_from_tool")
        metadata = [
            DojoMeta(
                finding_id=finding.id,
                name="dependency_track_analysis",
                value=json.dumps(parser.snapshot_analysis[finding.unique_id_from_tool], separators=(",", ":")),
            )
            for finding in findings
        ]
        if metadata:
            DojoMeta.objects.bulk_create(
                metadata, update_conflicts=True, unique_fields=["finding", "name"], update_fields=["value"], batch_size=1000,
            )


@transaction.atomic
def reconcile_missing_findings(importer, parser, *, close_missing):
    findings = list(importer.test.finding_set.filter(unique_id_from_tool__startswith=f"{parser.sync_project}:"))
    identity_counts = Counter(finding.unique_id_from_tool for finding in findings)
    markers = {
        marker.finding_id: marker
        for marker in DojoMeta.objects.filter(
            finding__test=importer.test,
            finding__unique_id_from_tool__startswith=f"{parser.sync_project}:",
            name="dependency_track_absent_since",
        )
    }
    closed = []
    for finding in findings:
        if finding.unique_id_from_tool in parser.snapshot_matrices:
            if marker := markers.get(finding.id):
                marker.delete()
            continue
        if not close_missing:
            continue
        if identity_counts[finding.unique_id_from_tool] != 1:
            continue
        marker = markers.get(finding.id)
        if marker is None:
            DojoMeta.objects.create(
                finding=finding, name="dependency_track_absent_since", value=parser.sync_timestamp.isoformat(),
            )
            continue
        try:
            previous_timestamp = parse_datetime(marker.value)
        except ValueError:
            previous_timestamp = None
        if previous_timestamp is None or not is_aware(previous_timestamp):
            logger.warning("Invalid Dependency-Track absence timestamp for finding %s", finding.id)
            continue
        if parser.sync_timestamp <= previous_timestamp:
            continue
        if finding.duplicate or finding.risk_accepted or finding.out_of_scope or finding.is_mitigated:
            continue
        finding.under_defect_review = False
        importer.mitigate_finding(
            finding,
            "No longer present in two complete Dependency-Track snapshots; the reason is not known.",
            finding_groups_enabled=importer.findings_groups_enabled,
            product_grading_option=False,
        )
        closed.append(finding.id)
    return closed
