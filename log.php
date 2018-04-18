<?php
require_once('conf/config.php');
require_once('Honeypot.class.php');

$hp = new Honeypot();
$hp->Log($_REQUEST['ip'],$_REQUEST['error'],$_REQUEST['target_url'],$_REQUEST['referrer']);
