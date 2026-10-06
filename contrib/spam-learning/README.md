Spam learning with Dovecot IMAPSieve
====================================

Teaches SpamAssassin (e.g. inside amavisd) from what users do in their mail clients: moving a message into
the `Spam` folder learns it as spam, moving it out of `Spam` (except to `Trash`) learns it as ham. This works
for every IMAP client, not just Horde, and the Horde container needs no access to SpamAssassin.

```
mail client / IMP ──IMAP MOVE──> Dovecot ──IMAPSieve──> sa-learn-queue.sh ──> /var/spool/sa-learn/{spam,ham}
                                                                                         │
                       sa-learn-spool.timer (every 5 min, as amavis) ──> sa-learn <──────┘
```

Dovecot only drops the message into a spool directory, so moves stay fast even for hundreds of messages. A
systemd timer then feeds the queue to `sa-learn` as the `amavis` user, so the mail user never needs access
to the Bayes database.

## Install on the mail server

Replace `vmail` with the user Dovecot delivers mail as (`doveconf -h mail_uid`), and `Spam` in the Dovecot
config if your spam folder has another name.

```
# Dovecot config (use 90-imapsieve-spam-dovecot2.3.conf on Dovecot 2.3; check with `dovecot --version`)
install -m 644 90-imapsieve-spam.conf /etc/dovecot/conf.d/

# Sieve scripts and the queueing script
install -d /etc/dovecot/sieve /etc/dovecot/sieve-pipe
install -m 644 report-spam.sieve report-ham.sieve /etc/dovecot/sieve/
sievec /etc/dovecot/sieve/report-spam.sieve
sievec /etc/dovecot/sieve/report-ham.sieve
install -m 755 sa-learn-queue.sh /etc/dovecot/sieve-pipe/

# Spool: the mail user writes, the amavis group reads and removes
install -d -o amavis -g amavis -m 0711 /var/spool/sa-learn
install -d -o vmail -g amavis -m 2770 /var/spool/sa-learn/spam /var/spool/sa-learn/ham

# Learner
install -m 755 sa-learn-spool.sh /usr/local/bin/
install -m 644 sa-learn-spool.service sa-learn-spool.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sa-learn-spool.timer

# IMAPSieve settings are only picked up on a full restart
systemctl restart dovecot
```

`sa-learn-spool.service` sets `HOME=/var/spool/amavisd`, where amavisd's SpamAssassin keeps its Bayes database
on Fedora/RHEL. Adjust it if `~amavis` is elsewhere on your system.

## Horde (IMP)

In `imp/backends.local.php`, report through the `null` driver, since the learning happens on the server:
```php
'spam' => array(
    'innocent' => array('display' => true, 'null' => true),
    'spam' => array('display' => true, 'null' => true),
),
```
and make IMP move the message after reporting, in `imp/prefs.local.php`:
```php
$_prefs['delete_spam_after_report']['value'] = 2;    // Move to Spam mailbox
$_prefs['delete_spam_after_report']['locked'] = true;
$_prefs['move_innocent_after_report']['value'] = 1;  // Move to Inbox
$_prefs['move_innocent_after_report']['locked'] = true;
```

## Checking it works

Move a message into `Spam`; a file should appear in `/var/spool/sa-learn/spam/`. After the next timer run
(or `systemctl start sa-learn-spool.service`) it is gone, `journalctl -u sa-learn-spool` shows
`Learned tokens from 1 message(s)`, and the counters go up:
```
sudo -u amavis HOME=/var/spool/amavisd sa-learn --dump magic | grep -E 'nspam|nham'
```

With SELinux enforcing, Dovecot may be denied running the script or writing to the spool. If no file appears,
check `ausearch -m avc -ts recent` and allow what is needed with a local policy module (`audit2allow -M`).
