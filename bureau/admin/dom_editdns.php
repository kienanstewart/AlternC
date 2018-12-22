<?php
/*
 ----------------------------------------------------------------------
 LICENSE

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License (GPL)
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 To read the license please visit http://www.gnu.org/copyleft/gpl.html
 ----------------------------------------------------------------------
*/

/**
 * Edit the DNS parameters of a domain
 * 
 * @copyright AlternC-Team 2000-2017 https://alternc.com/ 
 */

require_once("../class/config.php");
include_once("head.php");

$fields = array (
	"domain"    => array ("request", "string", ""),
	"dns"       => array ("post", "integer", 1),
	"email"     => array ("post", "integer", 1),
	"ttl"       => array ("post", "integer", 86400),
    'dnssec'    => array ('post', 'boolean', FALSE),
    'force'     => array ('post', 'boolean', FALSE),
);
getFields($fields);

$dom->lock();

$r = $dom->get_domain_all($domain);
if ($r["dns"] == $dns && $r["mail"] == $email && $r["zonettl"] == $ttl && $r['dnssec'] == $dnssec) {
  $msg->raise("INFO", "dom", _("No change has been requested..."));
} else if ($dom->edit_domain($domain,$dns,$email,$force,$ttl, $dnssec)) {
  $msg->raise("INFO", "dom", _("The domain %s has been changed."),$domain);
  $t = time();
// TODO: we assume the cron job is at every 5 minutes
  $msg->raise("INFO", "dom", _("The modifications will take effect at %s.  Server time is %s."), array(date('H:i:s', ($t-($t%300)+300)), date('H:i:s', $t)));
  // Reload the domain information to see if DnsSec changes were done.
  $dnssec_change_requested = $r['dnssec'] != $dnssec;
  $r = $dom->get_domain_all($domain);
  if ($dnssec_change_requested && ($r['dnssec'] == $dnssec)) {
      if ($r['dnssec']) {
          $msg->raise('INFO', 'dom', _('You have enabled DnsSec: Once the keys are generated and the zone signed you must get the DS entries from the DnsSec tab and upload them to your registrar, or enter them in to the parent zone.'));
      }
      else {
          $msg->raise('INFO', 'dom', _('You have disabled DnsSec: Make sure to remove DS entries from your registrar or the parent zone.'));
      }
  }
}
$dom->unlock();

include("dom_edit.php");
exit();
?>
