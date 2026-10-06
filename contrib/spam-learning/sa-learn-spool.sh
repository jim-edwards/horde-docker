#!/bin/sh
# Feeds the messages queued by sa-learn-queue.sh to SpamAssassin's Bayes
# database. Run as the amavis user by sa-learn-spool.timer.
set -eu
SPOOL=/var/spool/sa-learn

for kind in spam ham; do
    work="$SPOOL/.work-$kind"
    mkdir -p "$work"
    # Take only finished files; anything arriving meanwhile waits for the next run
    find "$SPOOL/$kind" -maxdepth 1 -type f ! -name '.*' -exec mv -t "$work" {} +
    if [ -n "$(find "$work" -type f -print -quit)" ]; then
        # On failure the files stay in $work and are retried next run
        sa-learn -L --"$kind" "$work"
        find "$work" -type f -delete
    fi
done
