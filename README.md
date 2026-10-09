Horde Groupware 6
=================

Horde 6 Groupware (Horde, Kronolith, Turba, Nag, Mnemo) with IMP webmail, Ingo filters, Passwd and ActiveSync,
installed with Composer from the [horde/bundle](https://github.com/horde/bundle) reference installation
on PHP 8.3 and Apache.

> Upgrading an existing Horde 5 container? Read [Upgrading from Horde 5](#upgrading-from-horde-5) first.
> The config volume moved, and the database schema upgrade can't be undone.
> The Horde 5 image is still available as `jimbo333/horde-docker:v5`, built from the `v5` branch.
> `jimbo333/horde-docker:latest` is the same as `:v6`.

### With local Database via Socket-Share
```
docker run --name ts_horde -d \
    -v /path/to/horde/config:/var/www/horde/var/config \
    -v [YOURSOCKET]:/var/run/mysqld/mysqld.sock \
    -p [YOURPORT]:80 \
    -e DB_NAME=[dbname] \
    -e DB_USER=[dbuser] \
    -e DB_PASS=[dbpassword] \
    jimbo333/horde-docker:v6
```

### With a Database over TCP
```
docker run --name ts_horde -d \
    -v /path/to/horde/config:/var/www/horde/var/config \
    -p [YOURPORT]:80 \
    -e DB_PROTOCOL=tcp \
    -e DB_HOST=[dbhost] \
    -e DB_PORT=3306 \
    -e DB_NAME=[dbname] \
    -e DB_USER=[dbuser] \
    -e DB_PASS=[dbpassword] \
    jimbo333/horde-docker:v6
```

On first start the container creates the database if it does not exist and loads the schema. Then log in, open
*Administration → Configuration* and save the configuration of each application once. An application has no
`conf.php` until you do, and until then its URL just sends you back to the portal.

If you need to run a database update later, run it as the web server user:
```
docker exec -it -u www-data ts_horde horde-db-migrate
```

Horde must be reached through a hostname that contains a dot (e.g. `horde.example.com`, or `horde.localhost` for
testing). Horde 6 refuses to set its session cookie for single-label names such as plain `localhost`.

### Behind an HTTPS reverse proxy

Pass the original host name and scheme through, otherwise Horde builds `http://` or wrong-host links to its
stylesheets and the page shows up unstyled. Apache (needs `mod_headers`):
```
ProxyPreserveHost On
RequestHeader set X-Forwarded-Proto "https"
ProxyPass / http://127.0.0.1:8080/
ProxyPassReverse / http://127.0.0.1:8080/
```
nginx: `proxy_set_header Host $host;` and `proxy_set_header X-Forwarded-Proto $scheme;`. Alternatively set
`$conf['use_ssl'] = 1;` in `horde/conf.php` to always generate https links.

The base application is served at `/horde/` (requests to `/` are forwarded there) and the other applications at
`/imp/`, `/kronolith/`, `/turba/` and so on. ActiveSync and Autodiscover are still answered at
`/Microsoft-Server-ActiveSync` and `/autodiscover/autodiscover.xml`.

### Spam reporting

The container has no access to SpamAssassin, so IMP's old `program` reporting (piping to `sa-learn`) does
not work. If your mail server runs Dovecot, let Dovecot learn whenever a message is moved into or out of the
Spam folder: see [contrib/spam-learning](contrib/spam-learning/README.md).

### DB default values
```
-e DB_HOST=localhost
-e DB_PORT=3306
-e DB_NAME=horde
-e DB_USER=horde
-e DB_PASS=horde
-e DB_PROTOCOL=unix          # unix (socket) or tcp
-e DB_SOCKET=/var/run/mysqld/mysqld.sock
-e DB_DRIVER=mysqli
```

The `$conf['sql']` connection settings in `horde/conf.php` are rewritten from these variables on every start, so set
them here rather than in the admin UI. Everything else in `conf.php` is yours to manage, either through
*Administration → Configuration* or by editing the file. `APACHE_UID`/`APACHE_GID` change the uid/gid of `www-data`
so it can match the owner of the volume on the host. `TZ` (e.g. `-e TZ=America/Phoenix`) also sets PHP's default
timezone, which Horde uses for users who have not picked their own.

Reminder e-mails for calendar events and tasks are sent by `horde-alarms`, which the container runs every
5 minutes by itself. `-e HORDE_ALARMS_INTERVAL=<seconds>` changes the interval, `0` turns it off.

### Volume expects each application to be in a separate directory
```
-v /path/to/horde/config:/var/www/horde/var/config

/var/www/horde/var/config/horde
/var/www/horde/var/config/imp
/var/www/horde/var/config/ingo
/var/www/horde/var/config/kronolith
/var/www/horde/var/config/mnemo
/var/www/horde/var/config/nag
/var/www/horde/var/config/passwd
/var/www/horde/var/config/turba
/var/www/horde/var/config/content
```

On every start the container copies the files the Horde installer manages into the volume: the `*.dist` templates,
each app's `horde.local.php`, and the generated `horde/registry.d/0*-*.php` files. Anything you create or edit there
(`conf.php`, `*.local.php`, `hooks.php`, your own `registry.d` snippets) is never overwritten. If `horde/conf.php` is
missing, a new one is generated from `conf.php.dist`, along with a random `$conf['secret_key']`.

Caches, logs, sessions, temp files and the file-based VFS live in `/var/www/horde/var/{cache,log,sessions,tmp,vfs}`.
Mount `/var/www/horde/var/vfs` as well if you use a file-based VFS backend, so attachments and files survive a
container rebuild.


Upgrading from Horde 5
----------------------

Horde 6 is not packaged by Debian/Ubuntu or PEAR any more, so this image is a rebuild rather than an update. The image
is now based on `php:8.3-apache` (Debian) instead of `phusion/baseimage:18.04`, Horde lives in `/var/www/horde`
instead of `/usr/share/horde`, and the configuration volume moved from `/etc/horde` to `/var/www/horde/var/config`.
Do not just point the new image at your old volume. The old `/etc/horde` contains copies of Horde 5's default config
files, and Horde 6 would load those on top of its own defaults.

The Horde 5 image also installed **Gollem** (file manager), **Trean** (bookmarks) and **Timeobjects**. Horde 6
versions of these exist only as beta/RC releases, so this image leaves them out. Their database tables are left
untouched. If you need them, build your own image from this one and add them:
```
FROM jimbo333/horde-docker:v6
RUN composer require --no-interaction --update-no-dev \
        "horde/trean:^2@RC" "horde/gollem:^5@beta" "horde/timeobjects:^3@beta" \
 && rm -rf /usr/local/share/horde/config-dist \
 && cp -a var/config /usr/local/share/horde/config-dist
```

### 1. Back up

Stop the Horde 5 container, then back up the database and the config volume:
```
docker stop ts_horde
mysqldump -u [dbuser] -p --single-transaction --routines horde > horde5-backup.sql
cp -a /path/to/horde/storage /path/to/horde/storage-h5-backup
```
The Horde 6 migration changes the database schema, and afterwards the database no longer works with Horde 5.
Rolling back means restoring this dump. Ideally, run the upgrade first against a copy of the database
(restore the dump into e.g. `horde6_test` and set `DB_NAME=horde6_test`).

### 2. Create a new config directory and copy over only your own files

Horde 6 ships its defaults inside the application (`vendor/horde/<app>/config/`) and only reads overrides from the
volume. Copy the files *you* wrote or changed. Leave out the stock files that came with Horde 5.

| Copy (per application dir)                        | Do **not** copy                                                                                 |
|---------------------------------------------------|-------------------------------------------------------------------------------------------------|
| `conf.php`                                        | `conf.xml`, `*.dist`                                                                            |
| `*.local.php` (`prefs.local.php`, `backends.local.php`, `registry.local.php`, `mime_drivers.local.php`, ...) | `horde.local.php` (now generated by the installer with the new paths) |
| `hooks.php`                                       | `prefs.php`, `backends.php`, `registry.php`, `mime_drivers.php`, `attributes.php`, `fields.php`, `nls.php`, `menu.php`, `motd.php` and other stock files |
| your own `horde/registry.d/*.php` snippets        |                                                                                                 |
| `conf-<vhost>.php` files, if you use vhosts       |                                                                                                 |

If you edited a stock file such as `prefs.php` or `backends.php` directly instead of using a `.local.php` file, move
those changes into the matching `.local.php` file. Don't copy the whole file, because it would replace Horde 6's
defaults.

For example:
```
OLD=/path/to/horde/storage-h5-backup
NEW=/path/to/horde/config
cd "$OLD"
for app in */; do
    app=${app%/}
    mkdir -p "$NEW/$app"
    for f in "$app"/conf.php "$app"/conf-*.php "$app"/hooks.php "$app"/*.local.php; do
        if [ -f "$f" ] && [ "$(basename "$f")" != horde.local.php ]; then
            cp -a "$f" "$NEW/$app/"
        fi
    done
done
for f in horde/registry.d/*.php; do
    if [ -f "$f" ]; then
        mkdir -p "$NEW/horde/registry.d" && cp -a "$f" "$NEW/horde/registry.d/"
    fi
done
```

### 3. Fix up the copied files

* **Registry paths**: in `horde/registry.local.php` and your `registry.d` snippets, remove or comment out any
  `fileroot` and `webroot` settings (for example `/usr/share/horde/...`). Horde 6 works these out itself, and the
  generated `horde/registry.d/0*-*.php` files set them for this image.
* **File system paths in `horde/conf.php`**: anything that pointed to `/var/cache/horde`, `/var/log/horde`,
  `/var/lib/horde` or `/tmp` should point to the matching directory under `/var/www/horde/var/`
  (`cache`, `log`, `vfs`, `tmp`). That covers `$conf['tmpdir']`, `$conf['log']['name']`, the file cache driver
  directory and a file-based `$conf['vfs']`. If you used a file-based VFS, copy its data to the new location (or
  mount it at `/var/www/horde/var/vfs`).
* **`hooks.php`**: Horde 6 runs on PHP 8.1+, while the old image ran PHP 7.2. Check any custom hooks for code that no
  longer works on PHP 8 (removed functions, stricter type errors, `each()`, curly-brace string offsets, etc.).
* **`$conf['use_ssl']`, `$conf['cookie']['domain']`, `$conf['server']['name']`**: check these still match how users
  reach the server. Note that the base app is now under `/horde/`.

The container also fixes a few things automatically on start:
* `$conf['sql']` connection settings are rewritten from the `DB_*` environment variables.
* `$conf['sql']['charset'] = 'utf-8'` (the Horde 5 default) is changed to `utf8mb4`, because current MySQL/MariaDB
  servers reject the plain `utf8` name it maps to.
* An empty `$conf['secret_key']` is replaced with a random one, because Horde 6 won't start without it.
  This logs out existing sessions, which happens during the upgrade anyway.
* If `conf.php` has no `$conf['share']['driver']` (it is only written once the Horde config has been saved in the
  admin UI), Horde's default `Sqlng` is added. Without it the Kronolith schema upgrade fails.

### 4. Start the Horde 6 container with the new volume

Use the run command from the top of this page. The volume target is now `/var/www/horde/var/config`. The
`HORDE_TEST_DISABLE` variable from the Horde 5 image is gone; use `$conf['testdisable']` in `conf.php` instead.

### 5. Upgrade the database schema

The database already exists, so the container will not migrate it on its own. Run:
```
docker exec -it -u www-data ts_horde horde-db-migrate
```
This upgrades every installed application to its Horde 6 schema. `horde-db-migrate` exits successfully even when one
application's migration fails, so read the output for `QUERY FAILED` or `Fatal Error` lines. After logging in,
*Administration → Configuration* should show "SQL DB schema is ready" for every application. Fix any problem, then
run the command again; it continues from where it stopped.

### 6. Update the configuration in the admin UI

Log in as an administrator, open *Administration → Configuration*, and for every application marked as out of date
open its configuration and save it. This adds the settings that are new in Horde 6 to each `conf.php`. It also creates
`conf.php` for any application that never had one; those applications won't open until you do this. Then check
`/horde/test.php` for missing PHP extensions or other problems, and set `$conf['testdisable'] = true;` again when done.

### Rolling back

Stop the Horde 6 container, restore `horde5-backup.sql` into the database, and start the old Horde 5 image
(`jimbo333/horde-docker:v5`) with the backed-up `/etc/horde` volume.
