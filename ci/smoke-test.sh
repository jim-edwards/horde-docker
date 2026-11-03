#!/bin/bash
#
# Checks that a freshly built Horde image is usable before it is published.
# Runs inside the image under test, with a MariaDB/MySQL server reachable
# through the DB_* variables (ci/verify-image.sh starts one). Exits non-zero
# if anything is wrong.
#
set -u

HORDE_DIR=${HORDE_DIR:-/var/www/horde}
LOG=$(mktemp)
failed=0

ok()   { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; failed=1; }
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else fail "$what"; fi; }

echo "== Installed software"
for ext in mysqli pdo_mysql intl gd imagick zip ldap gettext bcmath "Zend OPcache" memcached lzf; do
    check "PHP extension $ext" php -r 'exit(extension_loaded($argv[1]) ? 0 : 1);' "$ext"
done
for pkg in horde imp ingo kronolith turba nag mnemo passwd activesync; do
    check "horde/$pkg is installed" test -d "$HORDE_DIR/vendor/horde/$pkg"
done
check "Apache config is valid" apache2ctl -t
check "Apache mod_rewrite is enabled" sh -c 'apache2ctl -M 2>/dev/null | grep -q rewrite_module'
check "entrypoint scripts have valid syntax" bash -n /usr/local/bin/horde-init.sh /usr/local/bin/horde-alarms-loop.sh /docker-entrypoint.sh
check "Horde installer config is in place" test -f /usr/local/share/horde/config-dist/horde/conf.php.dist

# The Dockerfile patches IMP with sed and only prints a message if upstream changed the line it matches
if grep -q 'allow-popups' "$HORDE_DIR/vendor/horde/imp/lib/Mime/Viewer/Html.php"; then
    ok "IMP links in HTML mail are clickable (iframe sandbox patch applied)"
else
    fail "IMP iframe sandbox patch did not apply: upstream changed the line the Dockerfile sed matches, see https://github.com/horde/imp/issues/23"
fi

echo "== First start against an empty database"
mysql_args=(-h "${DB_HOST:?}" -P "${DB_PORT:-3306}" -u "${DB_USER:?}" --password="${DB_PASS:-}" --protocol=tcp)
# the entrypoint does not wait for the database, so a server that is still starting makes it skip the schema setup
for _ in $(seq 1 60); do
    mariadb-admin "${mysql_args[@]}" ping --silent >/dev/null 2>&1 && break
    sleep 2
done
check "database server is reachable" mariadb-admin "${mysql_args[@]}" ping --silent

# Apache signals its whole process group when it shuts down, which would kill this script, so give it its own
setsid /docker-entrypoint.sh apache2-foreground >"$LOG" 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null; rm -f "$LOG"' EXIT

started=0
for _ in $(seq 1 120); do
    if grep -q 'resuming normal operations' "$LOG"; then started=1; break; fi
    kill -0 "$server" 2>/dev/null || break
    sleep 2
done
if [ "$started" = 1 ]; then ok "container started Apache"; else fail "Apache did not start within 4 minutes"; fi

if grep -q '^Database created' "$LOG"; then ok "database and schema were created"; else fail "database was not created"; fi
# horde-db-migrate exits 0 even when a migration fails, so look for its messages
if grep -qE 'QUERY FAILED|Fatal Error|Creating database .* failed|Cannot connect to the database' "$LOG"; then
    fail "database setup reported errors"
else
    ok "database setup reported no errors"
fi
tables=$(mariadb "${mysql_args[@]}" -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '${DB_NAME:-horde}'" 2>/dev/null || echo 0)
if [ "${tables:-0}" -gt 20 ]; then ok "schema has $tables tables"; else fail "schema has only ${tables:-0} tables"; fi

# Horde refuses single-label host names such as localhost, so reach it as horde.localhost
page=$(mktemp)
code=$(curl -s -L --max-redirs 6 -c "$page.jar" -b "$page.jar" --resolve horde.localhost:80:127.0.0.1 \
    -o "$page" -w '%{http_code}' http://horde.localhost/ || true)
if [ "$code" = 200 ] && grep -q '<title>Horde ::' "$page" && ! grep -qi 'fatal error' "$page"; then
    ok "Horde serves its start page"
else
    fail "Horde start page: HTTP $code, $(grep -o '<title>[^<]*' "$page" | head -1)"
fi
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: horde.localhost' http://127.0.0.1/horde/test.php || true)
if [ "$code" = 200 ]; then ok "/horde/test.php responds"; else fail "/horde/test.php: HTTP $code"; fi
rm -f "$page" "$page.jar"

if [ "$failed" != 0 ]; then
    echo
    echo "== Container output"
    tail -n 60 "$LOG"
fi
exit "$failed"
