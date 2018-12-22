#!/usr/bin/php -q
<?php

require_once('/usr/share/alternc/panel/class/config_nochk.php');
ini_set('display_errors', 1);
$dom = new m_dom();

if (isset($argv[1])) {
    $domain = $argv[1];
    if (!$domain) {
        exit -1;
    }
}
else {
    exit -2;
}

if ($dom->generate_dnssec_keys($domain)) {
    exit;
}
exit -3;
