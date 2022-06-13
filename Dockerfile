# Pin to bionic because php-horde-* unavailable for 20.04 as at 2020-10-06
FROM phusion/baseimage:18.04-1.0.0

LABEL maintainer "Cheewai Lai <cheewai.lai@gmail.com>"

ARG DOCKERIZE_VERSION=v0.6.1
#
# TODO: figure out a smart automatic way to discover the path
#
ARG PHP_ETC_DIR=/etc/php/7.2

ENV HOME /root

ENV DB_NAME horde
ENV DB_USER horde
ENV DB_PASS horde
ENV DB_PROTOCOL unix
ENV DB_DRIVER mysqli
ENV HORDE_TEST_DISABLE false

RUN apt-get update
RUN apt-get install -y apache2 libapache2-mod-php mysql-client gnupg2 openssl php-pear \
	php-horde php-horde-imp php-horde-groupware php-horde-ingo php-horde-lz4 \
	php-imagick php-dev php-memcache php-memcached php-net-sieve && \
	pear channel-update pear.php.net && \
	#pear upgrade --force PEAR && \
        #apt-get -y install --reinstall php-xml && \
	pear install Net_DNS2 && \
	pecl install lzf \
 && echo extension=lzf.so > $PHP_ETC_DIR/mods-available/lzf.ini \
 && phpenmod lzf \
 && echo extension=horde_lz4.so > $PHP_ETC_DIR/mods-available/horde_lzf.ini \
 && phpenmod horde_lzf \
 && pear channel-discover pear.horde.org \
 && pear channel-update pear.horde.org \
 && pear upgrade-all \
 && apt-get -y install wget \
 && wget https://github.com/jwilder/dockerize/releases/download/$DOCKERIZE_VERSION/dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
 && tar -C /usr/bin -xzvf dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
 && rm dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
 && apt-get -y remove --purge wget \
 && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

EXPOSE 80

RUN mv /etc/horde /etc/.horde
ADD horde-init.sh /etc/my_init.d/horde-init.sh
ADD horde-base-settings.inc /etc/horde-base-settings.inc
RUN chmod +x /etc/my_init.d/horde-init.sh

RUN mkdir -p /etc/service/apache2
ADD run.sh /etc/service/apache2/run
RUN chmod +x /etc/service/apache2/run && \
	a2dissite 000-default && a2disconf php-horde

RUN mkdir -p /etc/apache2/scripts

ADD apache-horde.conf /etc/apache2/sites-available/horde.conf
RUN a2ensite horde

ADD docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/sbin/my_init"]
VOLUME /etc/horde
