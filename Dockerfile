FROM php:8.3-fpm-alpine

RUN apk add --no-cache linux-headers \
    && docker-php-ext-install sockets pcntl

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app

COPY composer.json ./
RUN composer install --no-dev --no-interaction --optimize-autoloader

COPY start.php index.php ./
COPY app ./app
COPY public ./public

RUN mkdir -p /app/storage && chown -R www-data:www-data /app/storage

EXPOSE 9000
CMD ["php-fpm"]
