#!/usr/bin/env bash

source conf/config.sh

#scan the access log for instances of someone using SQL keywords in their query string; filter out requests from Wittenberg (which will happen when using phpMyAdmin
# select the IP range with a sed regexp
# sort and count uniq instances
# write it to a log

egrep -i '\bUNION\b|\bSELECT\b|\bCHAR\b|\bNAME_CONST\b|\bUNHEX\b' $access_log | grep -v $ip_to_ignore | sed -n 's/\([0-9\.]\+\).*/\1/p' | sort | uniq -c > $injection_log

