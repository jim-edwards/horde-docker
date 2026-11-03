Keeping the image patched
=========================

Two GitHub workflows and a Dependabot config build the image, check that it works, scan it for known
vulnerabilities, publish it, and keep it current:

| What | When | Does |
|---|---|---|
| `build.yml` | pull request | builds the image, runs the smoke test and the scans. Publishes nothing, alerts nobody |
| `build.yml` | push to master | the same, then pushes `v6`, `latest` and a dated tag (`v6-20261102`) to Docker Hub, and updates the security issue |
| `build.yml` | every Sunday | the same as a push to master. A fresh build picks up new Debian packages and new Horde and Composer releases without any change to the repo |
| `security-watch.yml` | every day | scans the image that is *already published*, because CVEs get published after an image was built. Tells you about new ones, and starts a rebuild if that would fix them |
| `dependabot.yml` | every day | opens a pull request for a new PHP patch release (`FROM php:8.3.x-apache`), and weekly ones for Trivy, MariaDB and the GitHub Actions. `build.yml` merges the PHP patch releases itself once the image builds and passes the smoke test, then publishes |

The smoke test (`smoke-test.sh`) starts the image against an empty MariaDB, the way a new user would, and checks the
extensions, the Horde packages, the Dockerfile's IMP patch, the database migration and that Horde serves a page. It
is what lets a dependency update publish without anyone looking at it, so extend it when you add something to the
image. A build that fails it is never published, and the previous image stays as it was. If a rebuild turns out bad,
the dated tag of the day before is the way back.

`ci/verify-image.sh` does the smoke test and the scans, and is what the workflows run. You can run it yourself:
```
docker build -t horde-test .
ci/verify-image.sh horde-test                  # CONTAINER_CLI=podman to use podman
python3 ci/security_report.py --trivy reports/trivy.json --composer reports/composer-audit.json \
    --php-version reports/php-version.txt      # the report, without notifying anyone
python3 -m unittest discover -s ci             # the tests for security_report.py
```

What gets scanned
-----------------

* **Debian packages** (Apache, libraries, ImageMagick, ...) and **Composer packages** (Horde and its dependencies):
  [Trivy](https://trivy.dev) on the image, and `composer audit` in it.
* **PHP itself.** It is compiled from source in the base image, so neither of those sees it. It is checked against
  the [php-src security advisories](https://github.com/php/php-src/security/advisories), which name the fixed release
  for each branch, and against its end-of-life date (a warning 180 days ahead).
* **The PHP extensions the Dockerfile builds from GitHub tags** (Imagick, memcached), which Dependabot cannot see: a
  newer release shows up as an alert to change the version in the Dockerfile. It is a manual change on purpose,
  because these are compiled extensions.

What raises an alert
--------------------

An image has thousands of Debian findings with no fix yet. Alerting on all of them would bury the ones you can do
something about, so an alert needs one of:

* a fix is available (or it is in PHP or a Composer package), and the severity is HIGH or CRITICAL
* it is an OS package with no fix yet and the severity is CRITICAL

Everything else is only in the `scan-results` artifact of the run. The thresholds are the `CVE_MIN_SEVERITY` and
`CVE_UNFIXED_MIN_SEVERITY` environment variables of `ci/security_report.py` (`NONE` turns the second one off).

Alerts go to **one rolling issue**, labelled `security-alert`, mentioning the owner of the repository. It is opened
when the first alert appears, gets a comment (which is what sends the e-mail) whenever a *new* one shows up, and is
closed again when none apply any more. Close it yourself to acknowledge the current alerts: it stays quiet until a
different one appears. To stop alerting for a CVE for good, put it in `.trivyignore`, with an expiry date. If you set
the repository secret `NOTIFY_WEBHOOK_URL` (a Slack-compatible webhook: Slack, Mattermost, Rocket.Chat, or Discord
with `/slack` added) it is called too, when something new appears and when everything is clear again.

**This needs Issues turned on.** This repository is a fork, and forks start with Issues off (Settings → General →
Features). Until they are on, a run that finds alerts fails instead, which GitHub reports by e-mail like any failed run,
and the report is in the job summary. That repeats on every run, because nothing can remember that an alert was already reported.

What fixes itself, and what does not:

| Finding | What happens |
|---|---|
| Debian package, fix available | `security-watch.yml` starts `build.yml`, which installs the fix. If the next watch still sees it, it rebuilds again, at most once per `AUTO_REBUILD_MIN_AGE_HOURS` (20) |
| PHP patch release (CVE or not) | Dependabot opens the pull request the next morning at the latest; `build.yml` merges it when it is green, and the push to master publishes |
| Imagick or memcached release | alert only, change the version in the Dockerfile |
| Composer package | alert only. The weekly rebuild takes the newest release the version constraints allow; if that is still affected, only upstream or a constraint change helps |
| No fix released yet, PHP end of life | alert only |

If the PHP advisories, the end-of-life date or the extension tags cannot be fetched, the run fails (so you hear
about it) and the issue is left alone: an alert is never treated as resolved just because it could not be checked.

Things to know
--------------

* **Dependabot has to be running.** The pull requests appear under Insights → Dependency graph → Dependabot. If
  they do not, check Settings → Code security → Dependabot version updates (forks can have it off).
* **GitHub stops running scheduled workflows after 60 days without any activity in a public repository.**
  Merged Dependabot pull requests count as activity, but if the repository goes quiet, the daily scan can stop
  without anything else telling you. Enable the workflow again under Actions.
* The first run lists six CRITICAL findings that have no fix yet (OpenEXR, the MariaDB client libraries, libxml2, the
  kernel headers). They are accurate, and whether they matter to a container that has no MariaDB server or kernel is
  your decision: accept them in `.trivyignore`, or leave them as the baseline.
* `lzf` is built from a pinned commit, because the release it corresponds to has no tag, so nothing watches it.
* Debian packages are only as current as Debian's security tracker. A CVE Debian has not triaged is not reported by
  Trivy, however severe.
* Horde itself rarely has entries in the Packagist advisory database, so `composer audit` finding nothing says little
  about Horde's own bugs. The [Horde announcements](https://lists.horde.org/mailman/listinfo/announce) are where
  those are published.
