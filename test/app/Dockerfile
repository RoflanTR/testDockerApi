# Используем официальный PHP-образ с Apache
FROM php:8.1-apache

# Обновляем пакеты и устанавливаем зависимости
RUN apt-get update && apt-get install -y \
    libpq-dev \
    && docker-php-ext-install pdo pdo_pgsql \
    && apt-get clean; rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/share/doc/*

# Включаем модуль Apache mod_rewrite
RUN a2enmod rewrite

# Копируем исходный код приложения в /var/www/html
COPY . /var/www/html/

# Открываем порт 80
EXPOSE 80
