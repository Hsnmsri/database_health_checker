# Database Health Checker

Database health check, including checking for XSS data in the database.

# Installation

-   Clone Repository

```
git clone https://github.com/Hsnmsri/database_health_checker.git
```

-   Install Dependencies

```
composer install
```

-   Set Database Configs on .env file

```
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=
DB_USERNAME=
DB_PASSWORD=
```

# Using

- Check XSS injected data on database 
``` 
php artisan health:check-xss --yes
```
