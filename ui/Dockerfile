FROM php:8.3-apache

# pdo_mysql for persistence; zip to extract downloaded .nessus scan results
# (SimpleXML/DOM are bundled).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libzip-dev \
    && rm -rf /var/lib/apt/lists/* \
    && docker-php-ext-install pdo_mysql zip \
    && a2enmod headers

# Larger upload limits — .nessus exports can be several MB.
COPY php.ini /usr/local/etc/php/conf.d/zz-nessus.ini

# App lives in app/ (mounted as a volume in compose for live editing).
WORKDIR /var/www/html
COPY app/ /var/www/html/
