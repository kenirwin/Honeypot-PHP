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
5. In a directory that is writable be the webserver, create a web-writable blank file: `blacklist_ips.txt`
6. Copy `conf/sample_config.php` to `conf/config.php` and fill in the appropriate MySQL configurations and desired parameters.
   * `BLACKLIST` defines the full path to the location of the `blacklist_ips.txt` file from Step 5.
   * `CHECK_MINUTES` and `BAN_THRESHOLD` work together to set the tolerances for how many logged errors to accept in a particular timeframe, according to this formula: The IP or IP range will be blocked if there more than BAN_THRESHOLD logged errors in the past CHECK_MINUTES minutes.
   * `MATCHING_OCTETS` defines the level of specificity with IPs are matched. Each of the strings of digits in IP address is an octet. This setting defines how many octets (starting with the first) must match the string in order to be counted in the ban. Setting the value to 4 requires an exact IP match (e.g. 123.456.7.89) whereas a setting of 3 would match 123.456.7.*). I suggest setting the level at 3. 
   * `KEEP_LOG_DAYS` tells how many days to keep the logs for when the `purge.php` script runs
7. Set up Apache to use the blacklist
   * in main section of httpd.conf (right after the ErrorDocument definitions will work) include these two lines (skip the first is the RewriteEngine has already been turned on earlier in the file:
```
RewriteEngine On
RewriteMap access txt:/path/to/blacklist_ips.txt
```
   * in the `.htaccess` file of the web root folder include these lines:
```
RewriteEngine On
RewriteCond %{REMOTE_ADDR} ^(\d+)\.(\d+)\.(\d+)\.(\d+)$ 
RewriteRule .* - [E=Va:%1,E=Vb:%2,E=Vc:%3,E=Vd:%4] 
RewriteRule .* - [E=Four:%{ENV:Va}.%{ENV:Vb}.%{ENV:Vc}.%{ENV:Vd}]
RewriteRule .* - [E=Three:%{ENV:Va}.%{ENV:Vb}.%{ENV:Vc}.*]
RewriteRule .* - [E=Two:%{ENV:Va}.%{ENV:Vb}.*.*]
RewriteCond ${access:%{ENV:Four}} deny [OR]
RewriteCond ${access:%{ENV:Three}} deny [OR]
RewriteCond ${access:%{ENV:Two}} deny 
RewriteRule (.*) - [F]
```
8. Set up `cron` jobs to run `check.php` every minute or so, and `purge.php` once a day
   * `check.php` will look for new offending IPs; if any meets the threshold for banning, it will write them to the `honeypot_ips` table. It will then freshly export the contents of the table to the `blacklist_ips.txt` file, which will then inform the `.htaccess` file to deny further requests from the matching IPs or IP ranges. 
   * `purge.php` will delete items from the log after the number of days specified by the `KEEP_LOG_DAYS` configuration. It does *not* remove the banned IPs from the blacklist. That can only be done manually in the `honeypot_ips` table.

## Requirements

* PHP
* MySQL
* Apache with Mod_Rewrite

## Credits

Honeypot-PHP was developed by Ken Irwin, kirwin@wittenberg.edu

## License

This work is licensed under a Creative Commons Attribution 4.0 International License: https://creativecommons.org/licenses/by/4.0/