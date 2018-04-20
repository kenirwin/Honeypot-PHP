CREATE TABLE IF NOT EXISTS `honeypot_log` (
  `error_time` datetime NOT NULL,
  `error_code` int(11) NOT NULL,
  `ip` varchar(255) NOT NULL,
  `target_url` varchar(255) NOT NULL,
  `referrer` varchar(255) NOT NULL
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `honeypot_ips` (
  `ip` varchar(255) NOT NULL,
  `ban_date` date NOT NULL,
  PRIMARY KEY (`ip`)
) CHARSET=utf8;
