---
title: "Dependency Track"
toc_hide: true
aliases:
  - "/en/connecting_your_tools/parsers/file/dependency_track/"
---
Dependency Track has implemented a DefectDojo integration. Information about
how to configure the integration is documented here:
https://docs.dependencytrack.org/integrations/defectdojo/

Alternatively, the Finding Packaging Format (FPF) from OWASP Dependency Track can be
imported in JSON format. See here for more info on this JSON format:
<https://docs.dependencytrack.org/integrations/file-formats/>

### Dependency-Track-Owned Status

The optional synchronization reads a complete project snapshot, including suppressed
findings, from Dependency-Track on each import or reimport. It is disabled unless a
project is explicitly bound to a DefectDojo engagement and test title. Configure the
same settings on the Django and Celery containers:

- `DD_DEPENDENCY_TRACK_SYNC_URL`: trusted Dependency-Track API base URL, for example
  `http://apiserver:8080` when both services share a Docker network.
- `DD_DEPENDENCY_TRACK_SYNC_API_KEY`: a Dependency-Track API key with `VIEW_VULNERABILITY`
  and access to the bound projects. The `_FILE` form can be used for a secret file.
- `DD_DEPENDENCY_TRACK_SYNC_BINDINGS`: JSON mapping each project UUID to its DefectDojo
  engagement ID and test title, for example
  `{"ca4f2da9-0fad-4a13-92d7-f627f3168a56":{"engagement_id":42,"test_title":"Dependency-Track SCA"}}`.

Keep `DD_SERIALIZE_TEST_IMPORTS` enabled. To allow Dependency-Track to reopen a finding,
set the project's `defectdojo.doNotReactivate` property to `false`.

`IN_TRIAGE` sets **Under Defect Review**. Unassessed and in-triage findings are unverified;
`EXPLOITABLE` findings are verified. False positives, not-affected, resolved, and suppressed
findings are inactive. The exact analysis state and suppression flag are stored as finding
metadata. Duplicate, risk-accepted, and out-of-scope findings retain their local status.
The `isKev` flag updates **Known Exploited**; the KEV-added date is not synchronized.

A finding missing from the complete project snapshot is closed only after two snapshots
with distinct export timestamps report it missing. A repeated upload with the same timestamp
does not count twice. Closure means the finding is no longer reported, not necessarily that
the underlying vulnerability was patched. Failed or incomplete snapshots do not close findings.

### Sample Scan Data
Sample Dependency Track scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/dependency_track).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](/triage_findings/finding_deduplication/about_deduplication/):

- component name
- component version
- vulnerability ids
