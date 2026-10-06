require ["vnd.dovecot.pipe", "copy"];

# A message was copied or moved into the Spam folder: queue it for sa-learn --spam
pipe :copy "sa-learn-queue.sh" [ "spam" ];
