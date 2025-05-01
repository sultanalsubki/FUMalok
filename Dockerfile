FROM php:8.1-apache

# Install dependencies to compile PHP PostgreSQL extension
RUN apt-get update && apt-get install -y \
    libpq-dev \
    && docker-php-ext-install pdo pdo_pgsql

# Enable .htaccess mod_rewrite if needed
RUN a2enmod rewrite

# Copy project files into Apache web root
COPY . /var/www/html/

EXPOSE 80