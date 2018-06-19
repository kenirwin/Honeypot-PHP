<?php
require_once('conf/config.php');
require_once('Honeypot.class.php');

$hp = new Honeypot();
$hp->CheckLog();
$hp->CheckInjectionLog();
