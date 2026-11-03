#!/usr/bin/env python3
"""Turn the scan results for the Horde image into a security report and alerts.

Inputs, all produced by ci/verify-image.sh:
  --trivy        Trivy JSON report for the image (Debian packages, Composer packages)
  --composer     `composer audit --format=json` run inside the image
  --php-version  the PHP version in the image, or a file containing it

Trivy cannot see PHP itself (it is compiled from source in the base image), so
PHP is also checked against php-src's published security advisories and its
end-of-life date. The PHP extensions that the Dockerfile builds from GitHub tags
(which Dependabot cannot see) are checked for newer releases.

Not everything raises an alert, or the Debian packages alone (thousands of
"affected, no fix yet" entries) would drown out the useful ones:
  * a finding with a fix available, or in PHP or a Composer package, alerts
    from CVE_MIN_SEVERITY up (default HIGH)
  * an OS package finding with no fix yet alerts from CVE_UNFIXED_MIN_SEVERITY
    up (default CRITICAL, NONE turns it off)
  * IDs listed in .trivyignore are skipped (same file and syntax Trivy uses)

With --notify the alerts go to one rolling GitHub issue, which is created,
updated and closed as the set of alerts changes, and to NOTIFY_WEBHOOK_URL if
set. With --remediate, fixable OS package findings start a rebuild through the
GitHub API.
"""

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

SEVERITIES = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

GHSA_URL = "https://api.github.com/repos/php/php-src/security-advisories?state=published&per_page=100"
EOL_URL = "https://endoflife.date/api/php.json"
ISSUE_TITLE = "Security: vulnerabilities in the Horde image"
ISSUE_LABEL = "security-alert"
MAX_ROWS = 25  # per table; an image that is months old has hundreds of fixable findings
STATE_RE = re.compile(r"<!-- cve-state:(\[.*?\]) -->")


def rank(severity):
    return SEVERITIES.index(severity) if severity in SEVERITIES else 0


@dataclass(frozen=True)
class Finding:
    id: str  # CVE, GHSA or Packagist advisory id
    kind: str  # "os", "app" (Composer packages) or "php"
    package: str
    installed: str
    fixed: str  # "" when no fixed version is known
    severity: str
    title: str
    url: str


@dataclass
class Alert:
    """All findings with the same ID, e.g. one CVE in every binary package of a source package."""

    id: str
    kind: str
    severity: str
    packages: list
    installed: str
    fixed: str
    title: str
    url: str

    @property
    def remedy(self):
        if self.kind == "os" and self.fixed:
            return "rebuild"  # apt-get upgrade in a fresh build installs it
        if self.kind in ("php", "pin") and self.fixed:
            return "bump"  # the version pinned in the Dockerfile has to change
        return ""


# --- reading the scan results -------------------------------------------------------------


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise SystemExit(f"cannot read {path}: {e}")


def load_trivy(report):
    """Returns (findings, info) from a Trivy JSON report."""
    findings = []
    for result in report.get("Results") or []:
        kind = "os" if result.get("Class") == "os-pkgs" else "app"
        for v in result.get("Vulnerabilities") or []:
            findings.append(
                Finding(
                    id=v["VulnerabilityID"],
                    kind=kind,
                    package=v.get("PkgName", ""),
                    installed=v.get("InstalledVersion", ""),
                    fixed=v.get("FixedVersion", ""),
                    severity=(v.get("Severity") or "UNKNOWN").upper(),
                    title=v.get("Title") or v.get("Description", "")[:100],
                    url=v.get("PrimaryURL", ""),
                )
            )
    os_info = (report.get("Metadata") or {}).get("OS") or {}
    if os_info.get("EOSL"):
        name = f"{os_info.get('Family', 'OS')} {os_info.get('Name', '')}".strip()
        findings.append(
            Finding(
                id=f"EOL-{name.replace(' ', '-')}",
                kind="os",
                package=os_info.get("Family", "os"),
                installed=os_info.get("Name", ""),
                fixed="",
                severity="CRITICAL",
                title=f"The base image OS ({name}) is no longer supported and gets no security updates",
                url="",
            )
        )
    info = {
        # scanned from `docker save`, so ArtifactName is only the path of the tar file
        "image": next(iter((report.get("Metadata") or {}).get("RepoTags") or []), report.get("ArtifactName", "")),
        "os": f"{os_info.get('Family', '')} {os_info.get('Name', '')}".strip(),
        "created": parse_timestamp((report.get("Metadata") or {}).get("ImageConfig", {}).get("created")),
    }
    return findings, info


def load_composer(report):
    """Returns findings from `composer audit --format=json`. "advisories" is [] when empty, else {package: [..]}."""
    advisories = report.get("advisories") or {}
    if isinstance(advisories, list):
        advisories = {a.get("packageName", ""): [a] for a in advisories}
    findings = []
    for package, entries in advisories.items():
        for a in entries:
            findings.append(
                Finding(
                    id=a.get("cve") or a["advisoryId"],
                    kind="app",
                    package=a.get("packageName", package),
                    installed="",
                    fixed="",  # Composer reports the affected range, not the fix
                    severity=(a.get("severity") or "UNKNOWN").upper(),
                    title=a.get("title", ""),
                    url=a.get("link", ""),
                )
            )
    return findings


def parse_ignore(text, today=None):
    """IDs from a .trivyignore file: one per line, `# comments`, and `CVE-x exp:2027-01-31` expiry dates."""
    today = today or dt.date.today()
    ids = set()
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if not parts:
            continue
        expiry = next((p[4:] for p in parts[1:] if p.startswith("exp:")), None)
        if expiry:
            try:
                if dt.date.fromisoformat(expiry) < today:
                    continue
            except ValueError:
                pass
        ids.add(parts[0])
    return ids


def parse_timestamp(value):
    if not value:
        return None
    # Docker timestamps have nanoseconds, which datetime does not parse
    value = re.sub(r"(\.\d{6})\d*", r"\1", value).replace("Z", "+00:00")
    try:
        return dt.datetime.fromisoformat(value)
    except ValueError:
        return None


# --- PHP itself -----------------------------------------------------------------------------


def parse_version(text):
    m = re.match(r"\s*v?(\d+(?:\.\d+)*)", text or "")
    if not m:
        raise ValueError(f"not a version: {text!r}")
    return tuple(int(n) for n in m.group(1).split("."))


def _cmp(a, b):
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def in_range(version, spec):
    """Whether `version` is in a GitHub advisory range: '< 8.3.36', '>= 8.3.0, < 8.3.8', '8.1.0 - 8.1.9, 8.2.0 - 8.2.3'.

    php-src lists one entry per branch with an open-ended '< X' range, so a range
    without a lower bound only counts if X is on the same branch: '< 8.4.27' is
    numerically true for 8.3.36 but says nothing about 8.3.
    """
    v = parse_version(version)
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    if not parts:
        raise ValueError("empty range")
    if any(" - " in p for p in parts):
        for p in parts:
            low, _, high = p.partition(" - ")
            if _cmp(parse_version(low), v) <= 0 and _cmp(v, parse_version(high)) <= 0:
                return True
        return False
    has_lower = False
    upper = None
    for p in parts:
        m = re.match(r"^(<=|>=|<|>|=)?\s*v?(\d+(?:\.\d+)*)$", p)
        if not m:
            raise ValueError(f"unsupported range {spec!r}")
        op, bound = m.group(1) or "=", parse_version(m.group(2))
        c = _cmp(v, bound)
        if not {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "=": c == 0}[op]:
            return False
        if op in (">", ">=", "="):
            has_lower = True
        else:
            upper = bound
    if not has_lower and upper is not None and upper[:2] != v[:2]:
        return False
    return True


def php_findings(advisories, version):
    """Findings for the PHP `version` from the list of php-src GitHub security advisories."""
    findings, problems = [], []
    for adv in advisories:
        for vuln in adv.get("vulnerabilities") or []:
            try:
                if not in_range(version, vuln.get("vulnerable_version_range") or ""):
                    continue
            except ValueError as e:
                problems.append(f"{adv.get('ghsa_id')}: {e}")
                continue
            findings.append(
                Finding(
                    id=adv.get("cve_id") or adv["ghsa_id"],
                    kind="php",
                    package="php",
                    installed=version,
                    fixed=(vuln.get("patched_versions") or "").strip(),
                    severity=(adv.get("severity") or "UNKNOWN").upper(),
                    title=adv.get("summary", ""),
                    url=adv.get("html_url", ""),
                )
            )
            break  # one finding per advisory
    return findings, problems


def php_eol_findings(cycles, version, warn_days, today=None):
    """A finding when the PHP branch of `version` is within `warn_days` of its end of life, or past it."""
    today = today or dt.date.today()
    major_minor = ".".join(str(n) for n in parse_version(version)[:2])
    for cycle in cycles:
        if cycle.get("cycle") != major_minor:
            continue
        eol = cycle.get("eol")
        if not isinstance(eol, str):
            return []
        days = (dt.date.fromisoformat(eol) - today).days
        if days > warn_days:
            return []
        verb = "reached" if days < 0 else "reaches"
        return [
            Finding(
                id=f"EOL-PHP-{major_minor}",
                kind="php",
                package="php",
                installed=version,
                fixed="",
                severity="CRITICAL" if days < 0 else "HIGH",
                title=f"PHP {major_minor} {verb} end of security support on {eol}; move to a newer PHP branch",
                url="https://www.php.net/supported-versions.php",
            )
        ]
    return []


PIN_RE = re.compile(r"\s([\w.-]+/[\w.-]+)@(v?\d+\.\d+\.\d+)\b")


def pin_alerts(dockerfile, tags_of):
    """Alerts for `owner/repo@x.y.z` pins in the Dockerfile (PHP extensions that install-php-extensions builds from
    GitHub, which Dependabot cannot see) when the repository has a newer release tag. `tags_of(repo)` lists its tags."""
    alerts = []
    for repo, current in PIN_RE.findall(dockerfile):
        prefix = "v" if current.startswith("v") else ""
        newer = [t for t in tags_of(repo) if re.fullmatch(prefix + r"\d+\.\d+\.\d+", t) and _cmp(parse_version(t), parse_version(current)) > 0]
        if newer:
            latest = max(newer, key=parse_version)
            alerts.append(
                Alert(
                    id=f"UPDATE-{repo.replace('/', '-')}-{latest}",
                    kind="pin",
                    severity="UPDATE",
                    packages=[repo],
                    installed=current,
                    fixed=latest,
                    title=f"{repo} {latest} is out",
                    url=f"https://github.com/{repo}/releases/tag/{latest}",
                )
            )
    return alerts


def git_tags(repo):
    out = subprocess.run(["git", "ls-remote", "--tags", f"https://github.com/{repo}"], capture_output=True, text=True, timeout=60)
    if out.returncode:
        raise RuntimeError(f"git ls-remote {repo} failed: {out.stderr.strip()[:200]}")
    return [line.split("refs/tags/", 1)[1] for line in out.stdout.splitlines() if "refs/tags/" in line and not line.endswith("^{}")]


# --- deciding what is worth an alert --------------------------------------------------------


def select_alerts(findings, min_severity, unfixed_min_severity, ignored):
    """Applies the alert policy from the module docstring and groups findings by ID."""
    groups = {}
    for f in findings:
        if f.id in ignored:
            continue
        actionable = bool(f.fixed) or f.kind != "os"
        threshold = min_severity if actionable else unfixed_min_severity
        if threshold is None:
            continue
        # Packagist advisories mostly carry no severity; a known vulnerable package is worth an alert regardless
        if rank(f.severity) < rank(threshold) and not (f.severity == "UNKNOWN" and f.kind != "os"):
            continue
        groups.setdefault(f.id, []).append(f)
    alerts = []
    for id_, fs in groups.items():
        top = max(fs, key=lambda f: rank(f.severity))
        fixed = next((f.fixed for f in fs if f.fixed), "")
        installed = next((f.installed for f in fs if f.installed), "")
        alerts.append(
            Alert(
                id=id_,
                kind=top.kind,
                severity=top.severity,
                packages=sorted({f.package for f in fs}),
                installed=installed,
                fixed=fixed,
                title=next((f.title for f in fs if f.title), ""),
                url=next((f.url for f in fs if f.url), ""),
            )
        )
    alerts.sort(key=lambda a: (-rank(a.severity), a.id))
    return alerts


def cell(text, limit=90):
    text = (text or "").replace("|", "\\|").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def render_report(alerts, info, php_version, hidden, run_url=""):
    built = info["created"].strftime("%Y-%m-%d %H:%M UTC") if info.get("created") else "unknown"
    lines = [
        f"Scanned `{info.get('image') or 'image'}` (built {built}, {info.get('os') or 'unknown OS'}, PHP {php_version})"
        + (f" in [this run]({run_url})." if run_url else ".")
    ]
    fix = [a for a in alerts if a.fixed or a.kind != "os"]
    nofix = [a for a in alerts if not (a.fixed or a.kind != "os")]
    if not alerts:
        lines.append("\nNothing to act on.")
    for title, items in (("Fix or update available", fix), ("No fix released yet", nofix)):
        if not items:
            continue
        lines.append(f"\n### {title} ({len(items)})\n")
        lines.append("| ID | Severity | Package | Installed | Fixed in | Remedy |")
        lines.append("|---|---|---|---|---|---|")
        for a in items[:MAX_ROWS]:
            ident = f"[{a.id}]({a.url})" if a.url else a.id
            pkgs = ", ".join(f"`{p}`" for p in a.packages[:4]) + (f" +{len(a.packages) - 4}" if len(a.packages) > 4 else "")
            remedy = {
                "rebuild": "rebuild picks it up",
                "bump": "change the version in the Dockerfile" + (" (Dependabot proposes PHP)" if a.kind == "php" else ""),
            }.get(a.remedy) or ("wait for a Debian update" if a.kind == "os" else "see advisory")
            lines.append(
                f"| {ident}<br>{cell(a.title)} | {a.severity} | {pkgs} | {cell(a.installed, 30) or '-'} "
                f"| {cell(a.fixed, 30) or '-'} | {remedy} |"
            )
        if len(items) > MAX_ROWS:
            lines.append(f"\n…and {len(items) - MAX_ROWS} more, most severe first. All of them are in the Trivy report artifact.")
    lines.append(
        f"\n<sub>{hidden} other vulnerability IDs in the image are not listed: no fix released yet, below the severity "
        "threshold, or ignored. They are all in the Trivy report artifact. To accept a listed finding, add its ID to "
        "`.trivyignore`.</sub>"
    )
    return "\n".join(lines)


def with_state(report, alerts, mention=""):
    state = f"<!-- cve-state:{json.dumps(sorted(a.id for a in alerts))} -->"
    return "\n\n".join(part for part in (mention, report, state) if part)


def state_ids(issue):
    m = STATE_RE.search(issue.get("body") or "")
    return json.loads(m.group(1)) if m else []


# --- talking to the outside world -----------------------------------------------------------


class ApiError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class IssuesUnavailable(RuntimeError):
    pass


def http(method, url, headers=None, body=None, retries=3):
    """Returns (parsed JSON, response headers). Retries on network errors and 5xx."""
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"User-Agent": "horde-docker-ci", **(headers or {})}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                return (json.loads(raw) if raw.strip() else None), r.headers
        except urllib.error.HTTPError as e:
            if e.code < 500 or attempt == retries:
                raise ApiError(f"{method} {url.split('?')[0]} failed: HTTP {e.code} {e.read()[:300].decode(errors='replace')}", e.code)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt == retries:
                raise RuntimeError(f"{method} {url.split('?')[0]} failed: {e}")
        time.sleep(2 * attempt)


def fetch_php_advisories():
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    advisories, url = [], GHSA_URL
    while url:
        page, resp = http("GET", url, headers)
        advisories += page
        # this endpoint pages with cursors, only the Link header knows the next page
        nxt = re.search(r'<([^>]+)>;\s*rel="next"', resp.get("Link") or "")
        url = nxt.group(1) if nxt else None
    return advisories


def fetch_eol_cycles():
    return http("GET", EOL_URL)[0]


class GitHub:
    def __init__(self, api, repo, token):
        self.base, self.repo, self.token = api.rstrip("/"), repo, token

    def call(self, method, path, body=None, query=None):
        url = f"{self.base}/repos/{self.repo}{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        return http(method, url, headers, body)[0]

    def issues(self, state):
        """The newest issue with our label in `state` ("open" or "closed"), as a list of zero or one."""
        try:
            found = self.call(
                "GET", "/issues", query={"labels": ISSUE_LABEL, "state": state, "sort": "updated", "direction": "desc", "per_page": 5}
            )
        except ApiError as e:
            if e.status in (404, 410):  # forks start with Issues turned off
                raise IssuesUnavailable(str(e))
            raise
        return [i for i in found if "pull_request" not in i][:1]  # this endpoint lists pull requests too

    def create_issue(self, title, body):
        try:  # an unknown label is dropped silently, so make sure it exists
            self.call("POST", "/labels", {"name": ISSUE_LABEL, "color": "d73a4a", "description": "Vulnerabilities in the published image"})
        except ApiError as e:
            if e.status != 422:  # 422: already exists
                raise
        return self.call("POST", "/issues", {"title": title, "body": body, "labels": [ISSUE_LABEL]})

    def update_issue(self, number, **fields):
        return self.call("PATCH", f"/issues/{number}", fields)

    def comment(self, number, body):
        return self.call("POST", f"/issues/{number}/comments", {"body": body})

    def run_workflow(self, workflow, ref):
        return self.call("POST", f"/actions/workflows/{workflow}/dispatches", {"ref": ref})


def sync_issue(gh, alerts, report, mention="", partial=False):
    """Creates, updates or closes the rolling issue. Returns (issue, new IDs, all-clear?) when someone should be told.

    `partial` means a source could not be checked, so alerts missing from `alerts` are not known to be resolved:
    the issue then only gets what is new, and is never rewritten or closed.
    """
    ids = sorted(a.id for a in alerts)
    body = with_state(report, alerts, mention)
    opened = gh.issues("open")
    if opened:
        issue = opened[0]
        old = state_ids(issue)
        if ids == old:
            return None, [], False
        new = [i for i in ids if i not in old]
        if partial:
            if new:
                gh.comment(issue["number"], f"{mention} New: {', '.join(new)}. (Not every source could be checked this time.)".strip())
            return (issue, new, False) if new else (None, [], False)
        gone = [i for i in old if i not in ids]
        if not ids:
            gh.comment(issue["number"], f"{mention} All clear: {', '.join(gone)} no longer affect the image. Closing.".strip())
            gh.update_issue(issue["number"], state="closed", state_reason="completed", body=body)
            return issue, [], True
        gh.update_issue(issue["number"], body=body)
        if new:  # a comment, not the edit, is what sends the e-mail
            text = f"{mention} New: {', '.join(new)}."
            if gone:
                text += f" No longer affecting the image: {', '.join(gone)}."
            gh.comment(issue["number"], text.strip())
            return issue, new, False
        return None, [], False
    if not ids:
        return None, [], False
    closed = gh.issues("closed")
    if closed and set(ids) <= set(state_ids(closed[0])):
        return None, [], False  # closed by hand to acknowledge exactly these
    return gh.create_issue(ISSUE_TITLE, body), ids, False


def send_webhook(url, text):
    # `text` is read by Slack, Mattermost and Rocket.Chat, `content` by Discord
    http("POST", url, body={"text": text[:1800], "content": text[:1800]})


def remediate(gh, alerts, created, ref, min_age_hours, now=None):
    """Starts the rebuild that fixes fixable OS package alerts. Returns what it did, for the log.

    PHP and the extension pins are not rebuilt away: they need a change to the Dockerfile.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    done = []
    if any(a.remedy == "rebuild" for a in alerts):
        age = (now - created).total_seconds() / 3600 if created else None
        if age is None or age >= min_age_hours:
            gh.run_workflow("build.yml", ref)
            done.append("started a rebuild for fixable OS package vulnerabilities")
        else:
            done.append(f"fixable OS vulnerabilities, but the image was built {age:.0f}h ago; not rebuilding before {min_age_hours}h")
    return done


# --- main -----------------------------------------------------------------------------------


def severity_env(name, default):
    value = os.environ.get(name, default).strip().upper()
    if value in ("", "NONE"):
        return None
    if value not in SEVERITIES:
        raise SystemExit(f"{name} must be one of {', '.join(SEVERITIES)} or NONE, not {value!r}")
    return value


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trivy", required=True)
    ap.add_argument("--composer", required=True)
    ap.add_argument("--php-version", required=True)
    ap.add_argument("--ignore-file", default=".trivyignore")
    ap.add_argument("--dockerfile", default="Dockerfile", help="checked for pinned extension versions that have a newer release")
    ap.add_argument("--markdown", help="write the report here")
    ap.add_argument("--notify", action="store_true", help="open/update/close the GitHub issue and call the webhook")
    ap.add_argument("--remediate", action="store_true", help="start the rebuild that fixes fixable OS package findings")
    args = ap.parse_args(argv)

    min_severity = severity_env("CVE_MIN_SEVERITY", "HIGH")
    unfixed_min = severity_env("CVE_UNFIXED_MIN_SEVERITY", "CRITICAL")
    eol_days = int(os.environ.get("PHP_EOL_WARN_DAYS", "180"))
    min_age = float(os.environ.get("AUTO_REBUILD_MIN_AGE_HOURS", "20"))
    owner = os.environ.get("GITHUB_REPOSITORY_OWNER")
    mention = os.environ.get("NOTIFY_MENTION") or (f"@{owner}" if owner else "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_url = f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}" if os.environ.get("GITHUB_RUN_ID") else ""

    version_arg = args.php_version
    php_version = open(version_arg).read().strip() if os.path.exists(version_arg) else version_arg
    parse_version(php_version)

    findings, info = load_trivy(load_json(args.trivy))
    findings += load_composer(load_json(args.composer))

    warnings, failed = [], []
    try:
        found, problems = php_findings(fetch_php_advisories(), php_version)
        findings += found
        warnings += [f"skipped advisory {p}" for p in problems]
    except RuntimeError as e:
        failed.append(f"PHP advisories not checked: {e}")
    try:
        findings += php_eol_findings(fetch_eol_cycles(), php_version, eol_days)
    except (RuntimeError, ValueError) as e:
        failed.append(f"PHP end-of-life date not checked: {e}")

    ignored = parse_ignore(open(args.ignore_file).read()) if os.path.exists(args.ignore_file) else set()
    alerts = select_alerts(findings, min_severity, unfixed_min, ignored)
    if os.path.exists(args.dockerfile):
        try:
            pins = pin_alerts(open(args.dockerfile).read(), git_tags)
            alerts = sorted(alerts + [p for p in pins if p.id not in ignored], key=lambda a: (-rank(a.severity), a.id))
        except (RuntimeError, subprocess.SubprocessError) as e:
            failed.append(f"extension versions not checked: {e}")
    hidden = len({f.id for f in findings} - {a.id for a in alerts})

    report = render_report(alerts, info, php_version, hidden, run_url)
    if args.markdown:
        os.makedirs(os.path.dirname(args.markdown) or ".", exist_ok=True)
        with open(args.markdown, "w") as f:
            f.write(report + "\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(report + "\n")
    print(report)
    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)
    for f in failed:
        print(f"ERROR: {f}", file=sys.stderr)

    if not (args.notify or args.remediate):
        return 0
    # A source that could not be checked must not read as "nothing found", so alert about what is known, change
    # nothing else, and fail the job at the end so that a failed-workflow e-mail goes out
    exit_code = 4 if failed else 0

    token = os.environ.get("GITHUB_TOKEN")
    webhook = os.environ.get("NOTIFY_WEBHOOK_URL")
    gh = GitHub(os.environ.get("GITHUB_API_URL", "https://api.github.com"), repo, token) if token and repo else None

    if args.notify:
        issue, new, all_clear = (None, [], False)
        try:
            if not gh:
                raise IssuesUnavailable("GITHUB_TOKEN or GITHUB_REPOSITORY is not set")
            issue, new, all_clear = sync_issue(gh, alerts, report, mention, partial=bool(failed))
        except IssuesUnavailable as e:
            if alerts:
                # Failing the job is what makes GitHub e-mail the owner. It repeats on every run until the
                # alerts are fixed or put in .trivyignore, because nothing can remember that they were reported.
                print(f"ERROR: there are alerts but they cannot be put in an issue ({e}). On a fork, turn on "
                      "Settings > General > Features > Issues. The report is in the job summary.", file=sys.stderr)
                return 3
        link = f" {issue['html_url']}" if issue else ""
        if webhook and (new or all_clear):
            if all_clear:
                send_webhook(webhook, f"Horde image: all clear, the reported vulnerabilities no longer apply.{link}")
            else:
                shown = [a for a in alerts if a.id in new][:10]
                listing = "\n".join(f"- {a.id} {a.severity} {', '.join(a.packages[:3])}" for a in shown)
                more = f"\n…and {len(new) - len(shown)} more" if len(new) > len(shown) else ""
                send_webhook(webhook, f"Horde image: {len(new)} new vulnerabilit{'y' if len(new) == 1 else 'ies'}.{link}\n{listing}{more}")
        print(f"notified about {len(new)} new alert(s)" if new else "all clear sent" if all_clear else "no change since the last report")

    if args.remediate and alerts:
        if not gh:
            print("WARNING: cannot remediate without GITHUB_TOKEN", file=sys.stderr)
        else:
            for action in remediate(gh, alerts, info["created"], os.environ.get("DEFAULT_BRANCH", "master"), min_age):
                print(action)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
