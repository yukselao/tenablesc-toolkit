FROM php:8.3-apache

# pdo_mysql for the analysis-history persistence (SimpleXML/DOM are bundled).
RUN docker-php-ext-install pdo_mysql \
    && a2enmod headers

# Larger upload limits — .nessus exports can be several MB.
COPY php.ini /usr/local/etc/php/conf.d/zz-nessus.ini

# App lives in app/ (mounted as a volume in compose for live editing).
WORKDIR /var/www/html
COPY app/ /var/www/html/
