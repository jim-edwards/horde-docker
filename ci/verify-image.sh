#!/bin/bash
#
# Checks a built Horde image and collects what ci/security_report.py reads.
#
#   ci/verify-image.sh [--scan-only] IMAGE
#
# Unless --scan-only, it first runs ci/smoke-test.sh in IMAGE against a throwaway MariaDB. Then it writes
# reports/trivy.json, reports/composer-audit.json and reports/php-version.txt (REPORTS_DIR changes the directory).
# The scans run even when the smoke test failed; the exit status is the smoke test's.
#
# Uses docker, or podman with CONTAINER_CLI=podman. The Trivy and MariaDB versions are in ci/tools/Dockerfile.
# The Trivy vulnerability database is kept in TRIVY_CACHE_DIR (default ~/.cache/trivy).
#
set -euo pipefail

cli=${CONTAINER_CLI:-docker}
here=$(cd "$(dirname "$0")" && pwd)
out=$(mkdir -p "${REPORTS_DIR:-reports}" && cd "${REPORTS_DIR:-reports}" && pwd)
cache=$(mkdir -p "${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}" && cd "${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}" && pwd)

smoke=1
if [ "${1:-}" = --scan-only ]; then smoke=0; shift; fi
image=${1:?usage: verify-image.sh [--scan-only] IMAGE}

tool_image() { sed -n "s/^FROM \([^ ]*\) AS $1\$/\1/p" "$here/tools/Dockerfile"; }
trivy=$(tool_image trivy)
mariadb=$(tool_image mariadb)
[ -n "$trivy" ] && [ -n "$mariadb" ] || { echo "cannot read the tool images from $here/tools/Dockerfile" >&2; exit 2; }

work=$(mktemp -d)
net=horde-verify-$$
cleanup() {
    "$cli" rm -f "$net-db" >/dev/null 2>&1 || true
    "$cli" network rm "$net" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

status=0
if [ "$smoke" = 1 ]; then
    echo "== Smoke test"
    "$cli" network create "$net" >/dev/null
    "$cli" run -d --name "$net-db" --network "$net" -e MARIADB_ROOT_PASSWORD=ci-only "$mariadb" >/dev/null
    "$cli" run --rm --network "$net" -v "$here:/ci:ro,z" \
        -e DB_PROTOCOL=tcp -e DB_HOST="$net-db" -e DB_USER=root -e DB_PASS=ci-only \
        --entrypoint bash "$image" /ci/smoke-test.sh || status=$?
fi

echo "== PHP version and Composer advisories"
"$cli" run --rm --entrypoint php "$image" -r 'echo PHP_VERSION;' > "$out/php-version.txt"
# exits non-zero when it finds something, so only the JSON on stdout counts; security_report.py rejects a missing one
"$cli" run --rm --entrypoint composer -e COMPOSER_ALLOW_SUPERUSER=1 "$image" \
    audit --no-dev --locked --working-dir=/var/www/horde --format=json > "$out/composer-audit.json" || true

echo "== Trivy"
"$cli" save -o "$work/image.tar" "$image"
ignore=()
[ -f .trivyignore ] && ignore=(--ignorefile /work/.trivyignore)
"$cli" run --rm -v "$work:/in:ro,z" -v "$out:/out:z" -v "$cache:/cache:z" -v "$PWD:/work:ro,z" \
    -e TRIVY_CACHE_DIR=/cache -e TRIVY_NO_PROGRESS=true -e TRIVY_SKIP_JAVA_DB_UPDATE=true \
    "$trivy" image --input /in/image.tar --scanners vuln --format json --output /out/trivy.json "${ignore[@]}"

exit "$status"
