# Use official PHP image with Apache
FROM php:8.1-apache

# Enable mod_rewrite if you plan to use .htaccess routing (optional)
RUN a2enmod rewrite
RUN docker-php-ext-install pdo pdo_pgsql

# Copy all project files into the web root
COPY . /var/www/html/

# Expose port 80 (Apache default)
EXPOSE 80