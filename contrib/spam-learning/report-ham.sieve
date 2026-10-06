require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];

# A message was moved out of the Spam folder: queue it for sa-learn --ham,
# unless it was only being thrown away
if environment :matches "imap.mailbox" "*" {
  set "mailbox" "${1}";
}
if string "${mailbox}" "Trash" {
  stop;
}

pipe :copy "sa-learn-queue.sh" [ "ham" ];
