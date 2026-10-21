# Horde 6 is installed with Composer (horde/bundle) and requires PHP >= 8.1
# Pinned to the patch release; bump for PHP security fixes (8.3.36: CVE-2026-109618, CVE-2026-109619)
FROM php:8.3.36-apache

ENV HORDE_DIR=/var/www/horde
ENV PATH=$HORDE_DIR/vendor/bin:$PATH

ENV DB_HOST=localhost
ENV DB_PORT=3306
ENV DB_NAME=horde
ENV DB_USER=horde
ENV DB_PASS=horde
ENV DB_PROTOCOL=unix
ENV DB_DRIVER=mysqli

ADD --chmod=0755 https://github.com/mlocati/docker-php-extension-installer/releases/latest/download/install-php-extensions /usr/local/bin/
COPY --from=docker.io/library/composer:2 /usr/bin/composer /usr/bin/composer

# imagick, memcached and lzf are built from their GitHub sources instead of
# PECL, whose downloads were failing (same versions: imagick 3.8.1,
# memcached 3.4.0, lzf 1.7.0 = commit dd5a534a97ee)
RUN apt-get update \
 && apt-get install -y --no-install-recommends git unzip mariadb-client gnupg aspell aspell-en \
 && for i in 1 2 3 4 5; do \
	install-php-extensions mysqli pdo_mysql intl gd Imagick/imagick@3.8.1 zip ldap gettext bcmath opcache \
		php-memcached-dev/php-memcached@v3.4.0 php/pecl-file_formats-lzf@dd5a534a97ee && break; \
	[ "$i" = 5 ] && exit 1; echo "install-php-extensions failed, retrying in 60s"; sleep 60; \
    done \
 && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Groupware apps (horde, kronolith, turba, nag, mnemo) plus webmail, filters, password changing and ActiveSync
WORKDIR $HORDE_DIR
# The bundle also allows dev branches of the base packages; pin them to stable releases
RUN composer create-project --no-interaction --no-dev horde/bundle . "^1.1" \
 && composer require --no-interaction --update-no-dev \
	"horde/horde:^6" "horde/routes:^3" "horde/hordectl:^1" "horde/horde-installer-plugin:^3.4" \
	horde/imp horde/ingo horde/kronolith horde/turba horde/nag horde/mnemo "horde/passwd:^6@RC" horde/activesync \
 && composer clear-cache \
 && mkdir -p /usr/local/share/horde \
 && cp -a var/config /usr/local/share/horde/config-dist

# IMP 7 shows HTML mail in a sandboxed iframe without allow-popups, so links in
# messages (which IMP opens in a new window) cannot be clicked
# (https://github.com/horde/imp/issues/23). Scripts and forms stay blocked.
RUN f=vendor/horde/imp/lib/Mime/Viewer/Html.php \
 && if grep -q '<iframe sandbox="allow-same-origin"' $f; then \
	sed -i 's/<iframe sandbox="allow-same-origin"/<iframe sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox"/' $f; \
    else echo "IMP iframe sandbox changed upstream, link patch not applied"; fi

COPY php-horde.ini $PHP_INI_DIR/conf.d/horde.ini
COPY mysql-client.cnf /etc/mysql/mariadb.conf.d/99-horde-client.cnf
COPY horde-init.sh horde-alarms-loop.sh /usr/local/bin/
COPY horde-base-settings.inc /etc/horde-base-settings.inc
COPY apache-horde.conf /etc/apache2/sites-available/horde.conf
COPY docker-entrypoint.sh /docker-entrypoint.sh

RUN chmod +x /usr/local/bin/horde-init.sh /usr/local/bin/horde-alarms-loop.sh /docker-entrypoint.sh \
 && cp $PHP_INI_DIR/php.ini-production $PHP_INI_DIR/php.ini \
 && a2enmod rewrite \
 && a2dissite 000-default && a2ensite horde

EXPOSE 80

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["apache2-foreground"]
VOLUME /var/www/horde/var/config
