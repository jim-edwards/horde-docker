#!/bin/sh
# Called by Dovecot (IMAPSieve) as the mail user with the message on stdin.
# Only queues the message; sa-learn-spool.sh feeds the queue to sa-learn as
# the amavis user, so IMAP moves stay fast and need no extra privileges.
# Usage: sa-learn-queue.sh spam|ham
SPOOL=/var/spool/sa-learn

case "$1" in
    spam|ham) ;;
    *) exit 1 ;;
esac

tmp=$(mktemp "$SPOOL/$1/.new.XXXXXX") || exit 1
# mktemp creates 0600; the amavis group must be able to read it
chmod 0660 "$tmp"
if cat > "$tmp"; then
    mv "$tmp" "$SPOOL/$1/$(date +%s).${tmp##*.}"
else
    rm -f "$tmp"
    exit 1
fi
