Horde Groupware
==============

### With local Database via Socket-Share
```
docker run --name ts_horde -d \
    -v /path/to/horde/storage:/etc/horde \
    -v [YOURSOCKET]:/var/run/mysqld/mysqld.sock \
    -p [YOURPORT]:80 \
    -e HORDE_TEST_DISABLE=true \
    -e DB_NAME=[dbpassword] \
    -e DB_USER=[dbpassword] \
    -e DB_PASS=[dbpassword] \
    jim-edwards/horde-docker
```

Enter `horde-db-migrate` into an interactive shell on first run if you need a database update.

### DB default values
```
-e DB_HOST=localhost
-e DB_PORT=3306
-e DB_NAME=horde
-e DB_USER=horde
-e DB_PASS=horde
-e DB_PROTOCOL=SOCKET
-e DB_DRIVER=mysqli
```

### Disable test.php of horde by setting this to true
```
-e HORDE_TEST_DISABLE=false
```

### Volume expects each application to be in a seperate dierction
```
-v /path/to/horde/storage:/etc/horde

/etc/horde
/etc/horde/imp
/etc/horde/kronolith
/etc/horde/mnemo
/etc/horde/nag
/etc/horde/passwd
/etc/horde/ingo
/etc/horde/turba
```
