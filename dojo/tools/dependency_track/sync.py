from dojo.tools.dependency_track.client import DependencyTrackSyncError


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
