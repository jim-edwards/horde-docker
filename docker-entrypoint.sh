#! /bin/sh
#
# Docker entrypoint script to change UID/GID of Debian/Ubuntu Apache
# and prepare Horde before starting Apache
#
set -eu

[ "${DEBUG:-}" = 'yes' ] && set -x

[ -n "${APACHE_GID:-}" ] && {
  groupmod --gid $APACHE_GID www-data
}

[ -n "${APACHE_UID:-}" ] && {
  usermod --uid $APACHE_UID www-data
}

if [ "$1" = 'apache2-foreground' ]; then
  /usr/local/bin/horde-init.sh
  /usr/local/bin/horde-alarms-loop.sh &
fi

exec "$@"
