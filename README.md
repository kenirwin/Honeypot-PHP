# Honeypot-PHP
Log and block abusive IP addresses/IP ranges

1. logs 4xx http errors 
2. checks logs for "repeat offenders"
3. user sets threshold for how much activity warrants a ban
4. banned IPs are exported to a file to be read by .htaccess

## Setup

## Requirements

* PHP
* MySQL
* Apache with Mod_Rewrite

## Credits

Honeypot-PHP was developed by Ken Irwin, kirwin@wittenberg.edu

## License

This work is licensed under a Creative Commons Attribution 4.0 International License: https://creativecommons.org/licenses/by/4.0/