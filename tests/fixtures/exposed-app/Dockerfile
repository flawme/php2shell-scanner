ARG PHP_VERSION=8.4.2
FROM php:${PHP_VERSION}-fpm-alpine AS runtime
RUN docker-php-ext-install pdo_mysql
COPY . /var/www
FROM php:8.3.12-cli
