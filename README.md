# Honeypot-PHP
Log and block abusive IP addresses/IP ranges

1. logs 4xx http errors 
2. checks logs for "repeat offenders"
3. user sets threshold for how much activity warrants a ban
4. banned IPs are exported to a file to be read by .htaccess

## Setup

1. Download Honeypot-PHP 
2. Create MySQL tables using `tables.sql`
3. If you haven't already, in your server's `httpd.conf` table, create custom php-based error files. This documentation does not cover creation of custom error pages, but the basic httpd.conf code will look something like this (probably with more error codes specified):
```
ErrorDocument 400 /error.php
ErrorDocument 404 /error.php
``` 
4. In the php-based error pages (e.g. the `error.php` page describe above), include the following code:
```
require_once('/path/to/Honeypot-PHP/config.php');
require_once('/path/to/Honeypot-PHP/Honeypot.class.php');
$error = $_SERVER['REDIRECT_STATUS'];
$ip = $_SERVER['REMOTE_ADDR'];
$url = $_SERVER['REQUEST_URI'];
$link_from = $_SERVER['HTTP_REFERER'];
$hp = new Honeypot();
$hp->Log($ip, $error, $url, $link_from);
```
5. Copy `conf/sample_config.php` to `conf/config.php` and fill in the appropriate MySQL configurations and desired parameters.
   * `CHECK_MINUTES` and `BAN_THRESHOLD` work together to set the tolerances for how many logged errors to accept in a particular timeframe, according to this formula: The IP or IP range will be blocked if there more than BAN_THRESHOLD logged errors in the past CHECK_MINUTES minutes.
   * `MATCHING_OCTETS` defines the level of specificity with IPs are matched. Each of the strings of digits in IP address is an octet. This setting defines how many octets (starting with the first) must match the string in order to be counted in the ban. Setting the value to 4 requires an exact IP match (e.g. 123.456.7.89) whereas a setting of 3 would match 123.456.7.*). I suggest setting the level at 3. 
   * `KEEP_LOG_DAYS` tells how many days to keep the logs for when the `purge.php` script runs
6. Set up `cron` jobs to run `check.php` every minute or so, and `purge.php` once a day

## Requirements

* PHP
* MySQL
* Apache with Mod_Rewrite

## Credits

Honeypot-PHP was developed by Ken Irwin, kirwin@wittenberg.edu

## License

This work is licensed under a Creative Commons Attribution 4.0 International License: https://creativecommons.org/licenses/by/4.0/