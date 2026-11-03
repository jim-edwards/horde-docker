import contextlib
import datetime as dt
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock
from urllib.parse import parse_qs, urlparse

import security_report as sr


def finding(id, kind="os", fixed="", severity="HIGH", package="pkg", installed="1.0"):
    return sr.Finding(id, kind, package, installed, fixed, severity, f"title {id}", f"https://example.test/{id}")


class VersionRanges(unittest.TestCase):
    def test_ranges(self):
        cases = [
            ("8.3.35", "< 8.3.36", True),
            ("8.3.36", "< 8.3.36", False),
            ("8.3.35", "<8.3.36", True),
            ("8.3.36", "<= 8.3.36", True),
            ("8.3.10", ">= 8.3.0, < 8.3.8", False),
            ("8.3.7", ">= 8.3.0, < 8.3.8", True),
            ("8.3.7", "> 8.3.7, < 8.3.20", False),
            ("8.3.7", "8.3.7", True),
            ("8.3.9", "8.3.7", False),
            # one php-src entry per branch: another branch's open-ended range says nothing about 8.3
            ("8.3.36", "< 8.4.27", False),
            ("8.3.20", "< 8.3.36", True),
            # hyphen ranges, which php-src uses for older advisories (regression: high end was compared the wrong way)
            ("8.3.36", "8.2.0 - 8.2.19, 8.3.0 - 8.3.7", False),
            ("8.3.5", "8.2.0 - 8.2.19, 8.3.0 - 8.3.7", True),
            ("8.2.19", "8.2.0 - 8.2.19, 8.3.0 - 8.3.7", True),
            ("8.2.20", "8.2.0 - 8.2.19, 8.3.0 - 8.3.7", False),
        ]
        for version, spec, expected in cases:
            with self.subTest(version=version, spec=spec):
                self.assertEqual(sr.in_range(version, spec), expected)

    def test_unsupported_range_is_an_error_not_a_silent_miss(self):
        with self.assertRaises(ValueError):
            sr.in_range("8.3.36", "~> 8.3")
        with self.assertRaises(ValueError):
            sr.in_range("8.3.36", "")


class PhpAdvisories(unittest.TestCase):
    ADVISORIES = [
        {
            "ghsa_id": "GHSA-aaaa",
            "cve_id": "CVE-2026-1",
            "severity": "critical",
            "summary": "bad",
            "html_url": "https://github.com/php/php-src/security/advisories/GHSA-aaaa",
            "vulnerabilities": [
                {"vulnerable_version_range": "< 8.2.35", "patched_versions": "8.2.35"},
                {"vulnerable_version_range": "< 8.3.36", "patched_versions": "8.3.36"},
                {"vulnerable_version_range": "< 8.4.27", "patched_versions": "8.4.27"},
            ],
        },
        {"ghsa_id": "GHSA-bbbb", "cve_id": None, "severity": None, "vulnerabilities": [{"vulnerable_version_range": "weird"}]},
    ]

    def test_affected_version_gets_patched_version_and_one_finding(self):
        found, problems = sr.php_findings(self.ADVISORIES, "8.3.35")
        self.assertEqual([(f.id, f.severity, f.fixed, f.kind) for f in found], [("CVE-2026-1", "CRITICAL", "8.3.36", "php")])
        self.assertEqual(len(problems), 1)  # the unparseable range is reported, not swallowed

    def test_patched_version_is_clean(self):
        self.assertEqual(sr.php_findings(self.ADVISORIES, "8.3.36")[0], [])

    def test_eol(self):
        cycles = [{"cycle": "8.4", "eol": "2028-12-31"}, {"cycle": "8.3", "eol": "2027-12-31"}, {"cycle": "8.0", "eol": False}]
        today = dt.date(2027, 8, 1)
        self.assertEqual(sr.php_eol_findings(cycles, "8.3.36", 180, today)[0].severity, "HIGH")
        self.assertEqual(sr.php_eol_findings(cycles, "8.3.36", 180, dt.date(2027, 1, 1)), [])
        self.assertEqual(sr.php_eol_findings(cycles, "8.3.36", 180, dt.date(2028, 2, 1))[0].severity, "CRITICAL")
        self.assertEqual(sr.php_eol_findings(cycles, "8.4.1", 180, today), [])
        self.assertEqual(sr.php_eol_findings(cycles, "8.0.1", 180, today), [])  # eol: false = no date set


class Loaders(unittest.TestCase):
    def test_trivy(self):
        report = {
            "ArtifactName": "/in/image.tar",
            "Metadata": {
                "RepoTags": ["example/horde:v6"],
                "OS": {"Family": "debian", "Name": "13.7"},
                "ImageConfig": {"created": "2026-11-02T19:11:29.056504164Z"},
            },
            "Results": [
                {"Class": "os-pkgs", "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "curl", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH", "Title": "t"}]},
                {"Class": "lang-pkgs", "Type": "composer-vendor", "Vulnerabilities": [{"VulnerabilityID": "CVE-2", "PkgName": "horde/imp", "Severity": "MEDIUM"}]},
                {"Class": "lang-pkgs"},  # no Vulnerabilities key at all
            ],
        }
        findings, info = sr.load_trivy(report)
        self.assertEqual([(f.id, f.kind, f.fixed) for f in findings], [("CVE-1", "os", "2"), ("CVE-2", "app", "")])
        self.assertEqual(info["created"], dt.datetime(2026, 11, 2, 19, 11, 29, 56504, tzinfo=dt.timezone.utc))
        self.assertEqual(info["image"], "example/horde:v6")

    def test_trivy_flags_an_unsupported_os(self):
        findings, _ = sr.load_trivy({"Metadata": {"OS": {"Family": "debian", "Name": "11", "EOSL": True}}, "Results": []})
        self.assertEqual([(f.id, f.severity) for f in findings], [("EOL-debian-11", "CRITICAL")])

    def test_composer_empty_is_a_list_and_populated_is_a_dict(self):
        self.assertEqual(sr.load_composer({"advisories": [], "abandoned": []}), [])
        populated = {"advisories": {"a/b": [{"advisoryId": "PKSA-1", "packageName": "a/b", "title": "x", "cve": None, "link": "u"}]}}
        (f,) = sr.load_composer(populated)
        self.assertEqual((f.id, f.package, f.severity), ("PKSA-1", "a/b", "UNKNOWN"))

    def test_ignore_file(self):
        text = "# accepted\nCVE-1\nCVE-2 exp:2099-01-01  # until fixed\nCVE-3 exp:2020-01-01\n\n"
        self.assertEqual(sr.parse_ignore(text, dt.date(2026, 11, 2)), {"CVE-1", "CVE-2"})


class Policy(unittest.TestCase):
    def select(self, findings, ignored=(), unfixed="CRITICAL"):
        return sr.select_alerts(findings, "HIGH", unfixed, set(ignored))

    def test_only_fixable_os_findings_alert_at_high(self):
        alerts = self.select([finding("fixable", fixed="2"), finding("unfixed-high"), finding("fixable-low", fixed="2", severity="LOW")])
        self.assertEqual([a.id for a in alerts], ["fixable"])

    def test_unfixed_os_findings_alert_only_at_critical(self):
        alerts = self.select([finding("unfixed-critical", severity="CRITICAL"), finding("unfixed-high")])
        self.assertEqual([a.id for a in alerts], ["unfixed-critical"])
        self.assertEqual(self.select([finding("c", severity="CRITICAL")], unfixed=None), [])

    def test_php_and_composer_findings_alert_even_without_a_fix_or_severity(self):
        alerts = self.select([finding("pksa", kind="app", severity="UNKNOWN"), finding("php", kind="php", severity="HIGH")])
        self.assertEqual(sorted(a.id for a in alerts), ["php", "pksa"])

    def test_ignored_ids_are_skipped(self):
        self.assertEqual(self.select([finding("a", fixed="2")], ignored=["a"]), [])

    def test_one_alert_per_id_across_packages_sorted_by_severity(self):
        alerts = self.select(
            [finding("A", fixed="2", package="gpg"), finding("A", fixed="2", package="gnupg"), finding("B", fixed="3", severity="CRITICAL")]
        )
        self.assertEqual([a.id for a in alerts], ["B", "A"])
        self.assertEqual(alerts[1].packages, ["gnupg", "gpg"])

    def test_remedies(self):
        by_id = {a.id: a for a in self.select([finding("os", fixed="2"), finding("php", kind="php", fixed="8.3.37"), finding("pkg", kind="app")])}
        self.assertEqual((by_id["os"].remedy, by_id["php"].remedy, by_id["pkg"].remedy), ("rebuild", "bump", ""))


class FakeGitHub:
    """Minimal in-memory version of the GitHub API calls the script makes, served over real HTTP."""

    def __init__(self, issues_enabled=True):
        self.issues, self.comments, self.dispatches, self.labels, self.requests = [], [], [], [], []
        self.issues_enabled = issues_enabled
        self.pull_requests = []  # GitHub lists these among the issues too
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def respond(self, payload, status=200):
                body = json.dumps(payload).encode() if payload is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def handle_any(self, method):
                url = urlparse(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                outer.requests.append((method, url.path, self.headers.get("Authorization"), body))
                path = url.path.replace("/repos/o/r", "")
                if path.startswith("/issues") and not outer.issues_enabled:
                    return self.respond({"message": "Issues are disabled for this repo"}, 410)
                if method == "GET" and path == "/issues":
                    query = parse_qs(url.query)
                    state = query["state"][0]
                    assert query["labels"] == [sr.ISSUE_LABEL]
                    found = [i for i in outer.issues if i["state"] == state] + [p for p in outer.pull_requests if p["state"] == state]
                    return self.respond(list(reversed(found)))
                if method == "POST" and path == "/labels":
                    if sr.ISSUE_LABEL in outer.labels:
                        return self.respond({"message": "Validation Failed"}, 422)
                    outer.labels.append(body["name"])
                    return self.respond(body, 201)
                if method == "POST" and path == "/issues":
                    assert body["labels"] == [sr.ISSUE_LABEL] and sr.ISSUE_LABEL in outer.labels, "label must exist first"
                    issue = {"number": len(outer.issues) + 1, "state": "open", "html_url": "https://github.test/o/r/issues/1", **body}
                    outer.issues.append(issue)
                    return self.respond(issue, 201)
                if method == "PATCH" and path.startswith("/issues/"):
                    issue = outer.issues[int(path.rsplit("/", 1)[1]) - 1]
                    issue.update(body)
                    return self.respond(issue)
                if method == "POST" and path.endswith("/comments"):
                    outer.comments.append(body["body"])
                    return self.respond({}, 201)
                if method == "POST" and path.endswith("/dispatches"):
                    outer.dispatches.append((path.split("/")[-2], body))
                    return self.respond(None, 204)
                self.respond({"message": "404"}, 404)

            do_GET = lambda self: self.handle_any("GET")
            do_POST = lambda self: self.handle_any("POST")
            do_PATCH = lambda self: self.handle_any("PATCH")

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.api = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class IssueLifecycle(unittest.TestCase):
    def setUp(self):
        self.fake = FakeGitHub()
        self.addCleanup(self.fake.close)
        self.gh = sr.GitHub(self.fake.api, "o/r", "secret-token")

    def alerts(self, *ids):
        return [sr.Alert(i, "os", "HIGH", ["pkg"], "1", "2", "t", "") for i in ids]

    def sync(self, *ids):
        return sr.sync_issue(self.gh, self.alerts(*ids), "REPORT", "@jim")

    def test_creates_one_issue_then_stays_quiet_until_something_changes(self):
        issue, new, _ = self.sync("CVE-1")
        self.assertEqual(new, ["CVE-1"])
        self.assertIn("@jim", issue["body"])
        self.assertEqual(self.fake.issues[0]["labels"], [sr.ISSUE_LABEL])
        self.assertEqual(self.sync("CVE-1"), (None, [], False))
        self.assertEqual(len(self.fake.issues), 1)
        self.assertEqual(self.fake.comments, [])
        self.assertEqual({r[2] for r in self.fake.requests}, {"Bearer secret-token"})

    def test_the_label_is_created_once_and_an_existing_one_is_fine(self):
        self.sync("CVE-1")
        self.sync()  # closes
        self.sync("CVE-2")  # creates again: the label now exists, which GitHub answers with 422
        self.assertEqual(len(self.fake.issues), 2)

    def test_pull_requests_with_the_label_are_not_mistaken_for_the_issue(self):
        self.fake.pull_requests.append({"number": 9, "state": "open", "pull_request": {}, "body": '<!-- cve-state:["CVE-1"] -->'})
        issue, new, _ = self.sync("CVE-1")
        self.assertEqual(new, ["CVE-1"])
        self.assertEqual(len(self.fake.issues), 1)

    def test_a_new_alert_comments_so_the_mention_sends_an_email(self):
        self.sync("CVE-1")
        _, new, _ = self.sync("CVE-1", "CVE-2")
        self.assertEqual(new, ["CVE-2"])
        self.assertEqual(len(self.fake.comments), 1)
        self.assertIn("@jim New: CVE-2", self.fake.comments[0])
        self.assertEqual(sr.state_ids(self.fake.issues[0]), ["CVE-1", "CVE-2"])

    def test_resolving_some_updates_the_issue_without_a_comment(self):
        self.sync("CVE-1", "CVE-2")
        self.assertEqual(self.sync("CVE-1"), (None, [], False))
        self.assertEqual(sr.state_ids(self.fake.issues[0]), ["CVE-1"])
        self.assertEqual(self.fake.comments, [])

    def test_all_clear_closes_the_issue_and_a_later_alert_opens_a_new_one(self):
        self.sync("CVE-1")
        _, _, all_clear = self.sync()
        self.assertTrue(all_clear)
        self.assertEqual(self.fake.issues[0]["state"], "closed")
        self.assertIn("All clear", self.fake.comments[0])
        self.sync("CVE-3")
        self.assertEqual(len(self.fake.issues), 2)

    def test_closing_the_issue_by_hand_acknowledges_those_alerts_only(self):
        self.sync("CVE-1", "CVE-2")
        self.fake.issues[0]["state"] = "closed"
        self.assertEqual(self.sync("CVE-1", "CVE-2"), (None, [], False))
        self.assertEqual(self.sync("CVE-1"), (None, [], False))
        self.assertEqual(len(self.fake.issues), 1)
        self.sync("CVE-1", "CVE-9")
        self.assertEqual(len(self.fake.issues), 2)

    def test_a_source_that_could_not_be_checked_never_resolves_or_closes_anything(self):
        self.sync("CVE-1", "CVE-PHP")
        before = dict(self.fake.issues[0])
        # the PHP advisories could not be fetched, so CVE-PHP is missing from this run: that is not a fix
        self.assertEqual(sr.sync_issue(self.gh, self.alerts("CVE-1"), "R", "@jim", partial=True), (None, [], False))
        self.assertEqual(sr.sync_issue(self.gh, [], "R", "@jim", partial=True), (None, [], False))
        self.assertEqual(self.fake.issues[0], before)
        self.assertEqual(self.fake.comments, [])
        # but something new is still reported
        _, new, _ = sr.sync_issue(self.gh, self.alerts("CVE-1", "CVE-9"), "R", "@jim", partial=True)
        self.assertEqual(new, ["CVE-9"])
        self.assertEqual(self.fake.issues[0]["state"], "open")
        self.assertEqual(sr.state_ids(self.fake.issues[0]), ["CVE-1", "CVE-PHP"])

    def test_nothing_to_report_and_no_issue_does_nothing(self):
        self.assertEqual(self.sync(), (None, [], False))
        self.assertEqual(self.fake.issues, [])

    def test_disabled_issues_are_reported_as_such(self):
        self.fake.issues_enabled = False
        with self.assertRaises(sr.IssuesUnavailable):
            self.sync("CVE-1")

    def test_remediation_rebuilds_only_for_os_packages_and_respects_the_age_of_the_image(self):
        now = dt.datetime(2026, 11, 2, 12, tzinfo=dt.timezone.utc)
        alerts = [sr.Alert("CVE-1", "os", "HIGH", ["p"], "1", "2", "", ""), sr.Alert("CVE-2", "php", "HIGH", ["php"], "8.3.35", "8.3.36", "", "")]
        fresh = sr.remediate(self.gh, alerts, now - dt.timedelta(hours=2), "master", 20, now)
        self.assertIn("not rebuilding", fresh[0])
        self.assertEqual(self.fake.dispatches, [])
        sr.remediate(self.gh, alerts, now - dt.timedelta(hours=30), "master", 20, now)
        self.assertEqual(self.fake.dispatches, [("build.yml", {"ref": "master"})])
        self.fake.dispatches.clear()
        sr.remediate(self.gh, alerts[1:], now - dt.timedelta(hours=30), "master", 20, now)  # PHP needs a Dockerfile change
        self.assertEqual(self.fake.dispatches, [])


class Pins(unittest.TestCase):
    DOCKERFILE = (
        "RUN install-php-extensions mysqli Imagick/imagick@3.8.1 zip \\\n"
        "    php-memcached-dev/php-memcached@v3.4.0 php/pecl-file_formats-lzf@dd5a534a97ee && break\n"
    )
    TAGS = {
        "Imagick/imagick": ["3.8.1", "3.8.2", "3.9.0RC1", "3.10.0", "3.8.0RC2"],
        "php-memcached-dev/php-memcached": ["v3.4.0", "v3.3.0", "3.9.9", "v3.5.0RC1"],
    }

    def test_newer_release_tags_are_reported_and_prereleases_and_other_prefixes_are_not(self):
        alerts = sr.pin_alerts(self.DOCKERFILE, lambda repo: self.TAGS[repo])
        self.assertEqual([(a.id, a.installed, a.fixed) for a in alerts], [("UPDATE-Imagick-imagick-3.10.0", "3.8.1", "3.10.0")])

    def test_a_commit_pin_is_left_alone(self):
        self.assertEqual(sr.pin_alerts("php/pecl-file_formats-lzf@dd5a534a97ee", lambda repo: ["99.0.0"]), [])


class Main(unittest.TestCase):
    """The command line, with the network replaced and a fake GitHub."""

    def setUp(self):
        self.fake = FakeGitHub()
        self.addCleanup(self.fake.close)
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        for name, content in {
            "trivy.json": {"Results": []},
            "composer.json": {"advisories": []},
            "php.txt": "8.3.36",
        }.items():
            with open(f"{self.dir.name}/{name}", "w") as f:
                f.write(content if isinstance(content, str) else json.dumps(content))
        env = {"GITHUB_API_URL": self.fake.api, "GITHUB_REPOSITORY": "o/r", "GITHUB_TOKEN": "t", "GITHUB_REPOSITORY_OWNER": "jim"}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_main(self, *extra, advisories=(), eol=()):
        fetch = advisories if callable(advisories) else (lambda: list(advisories))
        args = ["--trivy", f"{self.dir.name}/trivy.json", "--composer", f"{self.dir.name}/composer.json",
                "--php-version", f"{self.dir.name}/php.txt", "--ignore-file", "/nonexistent", "--dockerfile", "/nonexistent", *extra]
        with mock.patch.object(sr, "fetch_php_advisories", fetch), mock.patch.object(sr, "fetch_eol_cycles", lambda: list(eol)):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return sr.main(args)

    ADVISORY = {"ghsa_id": "G", "cve_id": "CVE-PHP", "severity": "high", "vulnerabilities": [{"vulnerable_version_range": "< 8.3.40"}]}

    def open_issue(self):
        self.fake.issues.append({"number": 1, "state": "open", "body": '<!-- cve-state:["CVE-PHP"] -->', "html_url": "u"})

    def test_a_failed_php_lookup_fails_the_job_but_does_not_close_the_issue(self):
        self.open_issue()

        def broken():
            raise RuntimeError("GET failed: HTTP 403")

        self.assertEqual(self.run_main("--notify", advisories=broken), 4)
        self.assertEqual(self.fake.issues[0]["state"], "open")
        self.assertEqual(self.fake.comments, [])

    def test_a_clean_run_closes_the_issue(self):
        self.open_issue()
        self.assertEqual(self.run_main("--notify"), 0)
        self.assertEqual(self.fake.issues[0]["state"], "closed")

    def test_alerts_are_put_in_an_issue_that_mentions_the_owner(self):
        self.assertEqual(self.run_main("--notify", advisories=[self.ADVISORY]), 0)
        self.assertIn("@jim", self.fake.issues[0]["body"])
        self.assertIn("CVE-PHP", self.fake.issues[0]["body"])

    def test_alerts_that_cannot_go_in_an_issue_fail_the_job(self):
        self.fake.issues_enabled = False
        self.assertEqual(self.run_main("--notify", advisories=[self.ADVISORY]), 3)

    def test_disabled_issues_are_fine_when_there_is_nothing_to_report(self):
        self.fake.issues_enabled = False
        self.assertEqual(self.run_main("--notify"), 0)

    def test_without_notify_findings_are_not_a_failure(self):
        self.assertEqual(self.run_main(advisories=[self.ADVISORY]), 0)
        self.assertEqual(self.fake.issues, [])


class Report(unittest.TestCase):
    def test_report_renders_both_sections_and_escapes_table_cells(self):
        alerts = [
            sr.Alert("CVE-1", "os", "HIGH", ["a", "b", "c", "d", "e"], "1", "2", "has | a pipe", "https://x"),
            sr.Alert("CVE-2", "os", "CRITICAL", ["z"], "1", "", "no fix", ""),
        ]
        out = sr.render_report(alerts, {"image": "img", "os": "debian 13", "created": None}, "8.3.36", 4)
        self.assertIn("### Fix or update available (1)", out)
        self.assertIn("### No fix released yet (1)", out)
        self.assertIn("has \\| a pipe", out)
        self.assertIn("+1", out)
        self.assertIn("4 other vulnerability IDs", out)

    def test_long_tables_are_capped(self):
        alerts = [sr.Alert(f"CVE-{i}", "os", "HIGH", ["p"], "1", "2", "t", "") for i in range(sr.MAX_ROWS + 5)]
        out = sr.render_report(alerts, {"created": None}, "8.3.36", 0)
        self.assertEqual(out.count("| CVE-") + out.count("| [CVE-"), sr.MAX_ROWS)
        self.assertIn("…and 5 more", out)


if __name__ == "__main__":
    unittest.main()
