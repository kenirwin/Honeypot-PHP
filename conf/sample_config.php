<?php
define ('DB_HOST', '');
define ('DB_USER', '');
define ('DB_PASS', '');
define ('DB_DB', '');
define ('DB_CHARSET', 'utf8');
define ('BLACKLIST', ''); // /path/to/blacklist_ips.txt
define ('CHECK_MINUTES', 3); //check.php looks at errors in the last N minutes
define ('BAN_THRESHOLD', 8); //check.php will ban IP with more than N errors in the CHECK_MINUTES period
define ('MATCHING_OCTETS', 3); //1-4 (1=XXX.*.*.*, 4=exact IP, XXX.XXX.XXX.XXX)
define ('KEEP_LOG_DAYS', 7); //Delete after N days when purge.php runs