import json
from datetime import date
from unittest.mock import Mock, patch

from dojo.models import Test
from dojo.tools.dependency_track.client import fetch_project_findings
from dojo.tools.dependency_track.parser import DependencyTrackParser
from dojo.tools.dependency_track.sync import apply_analysis_status
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDependencyTrackParser(DojoTestCase):

    def test_dependency_track_parser_accepts_api_publication_timestamp(self):
        with (get_unit_tests_scans_path("dependency_track") / "one_finding.json").open(encoding="utf-8") as testfile:
            finding_data = json.load(testfile)["findings"][0]
        finding_data["vulnerability"]["published"] = 1752192000000

        finding = DependencyTrackParser()._convert_dependency_track_finding_to_dojo_finding(finding_data, Test())

        self.assertEqual(date(2025, 7, 11), finding.publish_date)

    @patch("dojo.tools.dependency_track.client.requests.get")
    def test_dependency_track_snapshot_fetches_all_pages(self, get):
        project = "ca4f2da9-0fad-4a13-92d7-f627f3168a56"
        first = {"matrix": f"{project}:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46"}
        second = {"matrix": f"{project}:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb47"}
        get.side_effect = [
            Mock(status_code=200, headers={"X-Total-Count": "2"}, json=Mock(return_value=[first])),
            Mock(status_code=200, headers={"X-Total-Count": "2"}, json=Mock(return_value=[second])),
        ]

        findings = fetch_project_findings("https://dependency-track.example", "secret", project, page_size=1)

        self.assertEqual([first, second], findings)
        self.assertEqual(2, get.call_count)
        self.assertEqual("true", get.call_args_list[0].kwargs["params"]["suppressed"])
        self.assertEqual(2, get.call_args_list[1].kwargs["params"]["pageNumber"])
        self.assertFalse(get.call_args_list[0].kwargs["allow_redirects"])

    @patch("dojo.tools.dependency_track.client.requests.get")
    def test_dependency_track_snapshot_rejects_changing_count(self, get):
        project = "ca4f2da9-0fad-4a13-92d7-f627f3168a56"
        finding = {"matrix": f"{project}:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46"}
        get.side_effect = [
            Mock(status_code=200, headers={"X-Total-Count": "2"}, json=Mock(return_value=[finding])),
            Mock(status_code=200, headers={"X-Total-Count": "1"}, json=Mock(return_value=[])),
        ]

        with self.assertRaises(ValueError):
            fetch_project_findings("https://dependency-track.example", "secret", project, page_size=1)

    @patch("dojo.tools.dependency_track.client.requests.get")
    def test_dependency_track_snapshot_rejects_incomplete_or_repeated_pages(self, get):
        project = "ca4f2da9-0fad-4a13-92d7-f627f3168a56"
        finding = {"matrix": f"{project}:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46"}

        for last_page in ([], [finding]):
            with self.subTest(last_page=last_page):
                get.side_effect = [
                    Mock(status_code=200, headers={"X-Total-Count": "2"}, json=Mock(return_value=[finding])),
                    Mock(status_code=200, headers={"X-Total-Count": "2"}, json=Mock(return_value=last_page)),
                ]
                with self.assertRaises(ValueError):
                    fetch_project_findings("https://dependency-track.example", "secret", project, page_size=1)

    @patch("dojo.tools.dependency_track.client.requests.get")
    def test_dependency_track_snapshot_rejects_redirects_and_missing_count(self, get):
        project = "ca4f2da9-0fad-4a13-92d7-f627f3168a56"
        for response in (
            Mock(status_code=302),
            Mock(status_code=200, headers={}, json=Mock(return_value=[])),
        ):
            with self.subTest(status=response.status_code):
                get.return_value = response
                with self.assertRaises(ValueError):
                    fetch_project_findings("https://dependency-track.example", "secret", project)

    @patch("dojo.tools.dependency_track.client.requests.get")
    def test_dependency_track_snapshot_accepts_confirmed_empty_project(self, get):
        project = "ca4f2da9-0fad-4a13-92d7-f627f3168a56"
        get.return_value = Mock(status_code=200, headers={"X-Total-Count": "0"}, json=Mock(return_value=[]))

        self.assertEqual([], fetch_project_findings("https://dependency-track.example", "secret", project))

    @patch("dojo.tools.dependency_track.client.requests.get")
    def test_dependency_track_snapshot_rejects_noncanonical_identity(self, get):
        project = "ca4f2da9-0fad-4a13-92d7-f627f3168a56"
        finding = {"matrix": f"{project}:B815B581-FEC1-4374-A871-68862A8F8D52:115b80bb-46c4-41d1-9f10-8a175d4abb46"}
        get.return_value = Mock(status_code=200, headers={"X-Total-Count": "1"}, json=Mock(return_value=[finding]))

        with self.assertRaises(ValueError):
            fetch_project_findings("https://dependency-track.example", "secret", project)

    def test_dependency_track_analysis_status_mapping(self):
        states = (
            (None, True, False, False, False, False),
            ("NOT_SET", True, False, False, False, False),
            ("IN_TRIAGE", True, False, False, False, True),
            ("EXPLOITABLE", True, True, False, False, False),
            ("FALSE_POSITIVE", False, False, True, True, False),
            ("NOT_AFFECTED", False, False, False, False, False),
            ("RESOLVED", False, False, False, True, False),
        )
        with (get_unit_tests_scans_path("dependency_track") / "one_finding.json").open(encoding="utf-8") as testfile:
            finding_data = json.load(testfile)["findings"][0]
        for state, active, verified, false_positive, mitigated, under_review in states:
            with self.subTest(state=state):
                finding = DependencyTrackParser()._convert_dependency_track_finding_to_dojo_finding(finding_data, Test())
                analysis = {"isSuppressed": False}
                if state is not None:
                    analysis["state"] = state
                apply_analysis_status(finding, analysis)
                self.assertEqual(active, finding.active)
                self.assertEqual(verified, finding.verified)
                self.assertEqual(false_positive, finding.false_p)
                self.assertEqual(mitigated, finding.is_mitigated)
                self.assertEqual(under_review, finding.under_defect_review)

    def test_dependency_track_suppressed_finding_is_inactive(self):
        with (get_unit_tests_scans_path("dependency_track") / "one_finding.json").open(encoding="utf-8") as testfile:
            finding_data = json.load(testfile)["findings"][0]
        finding = DependencyTrackParser()._convert_dependency_track_finding_to_dojo_finding(finding_data, Test())
        apply_analysis_status(finding, {"state": "EXPLOITABLE", "isSuppressed": True})

        self.assertFalse(finding.active)
        self.assertFalse(finding.verified)
        self.assertFalse(finding.is_mitigated)

    def test_dependency_track_rejects_invalid_analysis(self):
        for analysis in ({"state": []}, {"state": "UNKNOWN"}, {"isSuppressed": "false"}):
            with self.subTest(analysis=analysis), self.assertRaises(ValueError):
                apply_analysis_status(None, analysis)

    def test_dependency_track_parser_maps_kev_status(self):
        with (get_unit_tests_scans_path("dependency_track") / "one_finding.json").open(encoding="utf-8") as testfile:
            finding_data = json.load(testfile)["findings"][0]

        for is_kev in (True, False):
            with self.subTest(is_kev=is_kev):
                finding_data["vulnerability"]["isKev"] = is_kev
                finding = DependencyTrackParser()._convert_dependency_track_finding_to_dojo_finding(finding_data, Test())
                self.assertEqual(is_kev, finding.known_exploited)
                self.assertIsNone(finding.kev_date)

    def test_dependency_track_parser_with_empty_list_for_findings_key_has_no_findings(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "no_findings_because_findings_key_is_empty_list.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_dependency_track_parser_with_missing_findings_key_has_no_findings(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "no_findings_because_findings_key_is_missing.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_dependency_track_parser_with_null_findings_key_has_no_findings(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "no_findings_because_findings_key_is_null.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_dependency_track_parser_has_many_findings(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "many_findings.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))

            self.assertIn("533", findings[0].unsaved_vulnerability_ids)
            self.assertIn("48", findings[1].unsaved_vulnerability_ids)
            self.assertEqual(1, len(findings[2].unsaved_vulnerability_ids))
            self.assertEqual("CVE-2016-2097", findings[2].unsaved_vulnerability_ids[0])
            self.assertEqual("8d7f5fcd-210b-491d-a29e-904c2e01b281:3e52f829-3317-48c3-bde1-342c610bd223:900991f6-335a-49cb-9bf6-87b545f960ce", findings[2].unique_id_from_tool)
            self.assertEqual("900991f6-335a-49cb-9bf6-87b545f960ce", findings[2].vuln_id_from_tool)
            self.assertTrue(findings[2].false_p)
            self.assertTrue(findings[2].is_mitigated)
            self.assertFalse(findings[2].active)
            self.assertEqual(1, len(findings[3].unsaved_vulnerability_ids))
            self.assertEqual("CVE-2016-2097", findings[3].unsaved_vulnerability_ids[0])

    def test_dependency_track_parser_has_one_finding(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "one_finding.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            self.assertEqual(
                "ca4f2da9-0fad-4a13-92d7-f627f3168a56:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46",
                findings[0].unique_id_from_tool,
            )
            self.assertEqual(
                "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                findings[0].cvssv3,
            )
            self.assertEqual(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
                findings[0].cvssv4,
            )
            self.assertIn("https://example.com", findings[0].references)
            self.assertIn("https://example.org", findings[0].references)
            self.assertEqual(date(2025, 7, 11), findings[0].publish_date)

    def test_dependency_track_parser_v3_8_0(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "dependency_track_3.8.0_2021-01-18.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(9, len(findings))
            self.assertTrue(all(item.file_path is not None for item in findings))
            self.assertTrue(all(item.vuln_id_from_tool is not None for item in findings))
            self.assertTrue(all(item.unique_id_from_tool is not None for item in findings))

    def test_dependency_track_parser_findings_with_alias(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "many_findings_with_alias.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(12, len(findings))
            self.assertTrue(all(item.file_path is not None for item in findings))
            self.assertTrue(all(item.unique_id_from_tool is not None for item in findings))
            self.assertTrue(all(item.vuln_id_from_tool is not None for item in findings))
            self.assertTrue(all(item.unique_id_from_tool is not None for item in findings))
            self.assertIn("CVE-2022-42004", findings[0].unsaved_vulnerability_ids)
            self.assertIn("DSA-5283-1", findings[0].unsaved_vulnerability_ids)
            self.assertIn("GHSA-rgv9-q543-rqg4", findings[0].unsaved_vulnerability_ids)

    def test_dependency_track_parser_findings_with_empty_alias(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "many_findings_with_empty_alias.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(12, len(findings))
            self.assertIn("CVE-2022-2053", findings[11].unsaved_vulnerability_ids)

    def test_dependency_track_parser_npm_4_14_1(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "deptrack_npm_4.14.1.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(22, len(findings))
            # findings with GITHUB source and empty aliases should still have their GHSA id captured
            self.assertIn("GHSA-q4gf-8mx6-v5v3", findings[4].unsaved_vulnerability_ids)
            self.assertIn("GHSA-w5hq-g745-h8pq", findings[16].unsaved_vulnerability_ids)
            # findings with aliases should include both the vulnId and alias ids
            self.assertIn("GHSA-3p68-rc4w-qgx5", findings[2].unsaved_vulnerability_ids)
            self.assertIn("CVE-2025-62718", findings[2].unsaved_vulnerability_ids)

    def test_dependency_track_parser_php_4_14_1(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "deptrack_php_4.14.1.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(13, len(findings))
            # finding with GITHUB source and empty aliases should still have its GHSA id captured
            self.assertIn("GHSA-qrr6-mg7r-m243", findings[12].unsaved_vulnerability_ids)
            # findings with aliases should include both the vulnId and alias ids
            self.assertIn("GHSA-4486-gxhx-5mg7", findings[0].unsaved_vulnerability_ids)
            self.assertIn("CVE-2026-25129", findings[0].unsaved_vulnerability_ids)

    def test_dependency_track_parser_ghsa_vulnid_with_empty_aliases(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "one_finding_ghsa_empty_aliases.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            self.assertIn("GHSA-w5hq-g745-h8pq", findings[0].unsaved_vulnerability_ids)

    def test_dependency_track_parser_findings_with_cvssV3_score(self):
        with (get_unit_tests_scans_path("dependency_track") / "many_findings_with_cvssV3_score.json").open(encoding="utf-8") as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(12, len(findings))
        self.assertTrue(all(item.file_path is not None for item in findings))
        self.assertTrue(all(item.unique_id_from_tool is not None for item in findings))
        self.assertTrue(all(item.vuln_id_from_tool is not None for item in findings))
        self.assertTrue(all(item.unique_id_from_tool is not None for item in findings))
        self.assertIn("CVE-2022-42004", findings[0].unsaved_vulnerability_ids)
        self.assertEqual(8.3, findings[0].cvssv3_score)

    def test_dependency_track_parser_findings_with_epss_score(self):
        with (get_unit_tests_scans_path("dependency_track") / "dependency_track_4.10_2024_02_11.json").open(encoding="utf-8") as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        self.assertEqual(0.00043, findings[0].epss_score)
        self.assertEqual(0.07756, findings[0].epss_percentile)
        self.assertEqual(4.2, findings[0].cvssv3_score)
        self.assertIn("CVE-2023-45803", findings[0].unsaved_vulnerability_ids)

    def test_dependency_track_parser_finding_with_analysis_detail(self):
        with (get_unit_tests_scans_path("dependency_track") / "one_finding_with_analysis_detail.json").open(encoding="utf-8") as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        self.assertIn("Audit Detail: Reviewed and confirmed vulnerable. Upgrade scheduled for next sprint.", findings[0].description)

    def test_dependency_track_parser_finding_with_affected_versions(self):
        with (get_unit_tests_scans_path("dependency_track") / "one_finding_with_affected_versions.json").open(encoding="utf-8") as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        self.assertIn("Upgrade to 2.15.0 or later", findings[0].mitigation)

    def test_dependency_track_parser_finding_picks_range_containing_component_version(self):
        with (get_unit_tests_scans_path("dependency_track") / "finding_with_multiple_affected_ranges.json").open(encoding="utf-8") as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        # The installed version 2.14.1 falls in the [2.0.0, 2.15.0) range, so the fix is 2.15.0,
        # not the 3.2.0 from the unrelated [3.0.0, 3.2.0) range.
        self.assertIn("Upgrade to 2.15.0 or later", findings[0].mitigation)
        self.assertNotIn("3.2.0", findings[0].mitigation)

    def test_dependency_track_parser_finding_with_end_including_range(self):
        with (get_unit_tests_scans_path("dependency_track") / "finding_with_affected_range_end_including.json").open(encoding="utf-8") as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        # The range gives only versionEndIncluding (1.5.0 is the last affected version), so the exact
        # fix cannot be named; the mitigation points at a version after it.
        self.assertIn("Upgrade to a version after 1.5.0", findings[0].mitigation)

    def test_dependency_track_parser_finding_ignores_exact_version_entry(self):
        with (get_unit_tests_scans_path("dependency_track") / "finding_with_exact_and_range_versions.json").open(encoding="utf-8") as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        # The exact-version entry (1.0.0, no bounds) must not swallow the finding; the fix comes from
        # the range [2.0.0, 2.15.0) that the installed 2.14.1 actually falls in.
        self.assertIn("Upgrade to 2.15.0 or later", findings[0].mitigation)

    def test_dependency_track_parser_finding_with_unparseable_component_version(self):
        with (get_unit_tests_scans_path("dependency_track") / "finding_with_unparseable_component_version.json").open(encoding="utf-8") as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        # The component version does not parse, so no range can be compared; with a single affected
        # range the fix is still unambiguous and is used as a fallback.
        self.assertIn("Upgrade to 3.0.0 or later", findings[0].mitigation)
