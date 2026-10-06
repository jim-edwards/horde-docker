#!/bin/sh
#
# Runs horde-alarms periodically so reminder e-mails are sent without a
# cron job on the host. HORDE_ALARMS_INTERVAL is in seconds; 0 disables it.
#
INTERVAL=${HORDE_ALARMS_INTERVAL:-300}

[ "$INTERVAL" -gt 0 ] 2>/dev/null || exit 0

while sleep "$INTERVAL"; do
    timeout "$INTERVAL" setpriv --reuid=www-data --regid=www-data --init-groups \
        "$HORDE_DIR/vendor/bin/horde-alarms" || echo "horde-alarms failed" >&2
done
