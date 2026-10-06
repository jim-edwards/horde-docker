# Horde 6 is installed with Composer (horde/bundle) and requires PHP >= 8.1
FROM php:8.3-apache

ENV HORDE_DIR /var/www/horde
ENV PATH $HORDE_DIR/vendor/bin:$PATH

ENV DB_HOST localhost
ENV DB_PORT 3306
ENV DB_NAME horde
ENV DB_USER horde
ENV DB_PASS horde
ENV DB_PROTOCOL unix
ENV DB_DRIVER mysqli

ADD --chmod=0755 https://github.com/mlocati/docker-php-extension-installer/releases/latest/download/install-php-extensions /usr/local/bin/
COPY --from=docker.io/library/composer:2 /usr/bin/composer /usr/bin/composer

RUN apt-get update \
 && apt-get install -y --no-install-recommends git unzip mariadb-client gnupg aspell aspell-en \
 && install-php-extensions mysqli pdo_mysql intl gd imagick zip ldap gettext bcmath opcache memcached lzf \
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
