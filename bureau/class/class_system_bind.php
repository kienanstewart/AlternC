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
 * bind9 file management class
 * 
 * @copyright AlternC-Team 2000-2017 https://alternc.com/
 */
class system_bind {
    var $ZONE_TEMPLATE ="/etc/alternc/templates/bind/templates/zone.template";
    var $NAMED_TEMPLATE ="/etc/alternc/templates/bind/templates/named.template";
    var $NAMED_CONF ="/var/lib/alternc/bind/automatic.conf";
    var $RNDC ="/usr/sbin/rndc";

    var $dkim_trusted_host_file = "/etc/opendkim/TrustedHosts";
    var $dkim_keytable_file = "/etc/opendkim/KeyTable";
    var $dkim_signingtable_file = "/etc/opendkim/SigningTable";

    var $cache_conf_db = array();
    var $cache_get_persistent = array();
    var $cache_zone_file = array();
    var $cache_domain_summary = array();

    // @Note: The trailing slash is required on this variable since other code
    // assumes it is present when generating file paths.
    var $zone_file_directory = '/var/lib/alternc/bind/zones/';

    static public $DNSSEC_KEY_BASEDIR = "/var/lib/alternc/bind/keys";
    static public $DNSSEC_SETFILE_BASEDIR = "/var/lib/alternc/bind/setfiles";
    static public $dnssec_key_limits = array(
        'KSK/ZSK' => array(
            // RSAMD5 should never be used, though it could be valid for dnssec-keygen.
            // RSASHA1 should never be used, thought it could be valid.
            'NSEC3RSASHA1' => array(
                'min' => 512,
                'max' => 2048,
            ),
            'NSEC3DSA' => array(
                'min' => 512,
                'max' => 1024,
                'other' => '%64', // Exact multiple of 64.
            ),
            'RSASHA256' => array(
                'min' => 512,
                'max' => 2048,
            ),
            'RSASHA512' => array(
                'min' => 512,
                'max' => 2048,
            ),
            'ECDSAP256SHA256' => array(
                // Keysize parameter is ignored.
                'min' => 0,
                'max' => 10000,
            ),
            'ECDSAP384SHA384' => array(
                // Keysize parameter is ignored.
                'min' => 0,
                'max' => 10000,
            ),
        ),
        'TSIG/TKEY' => array(
            // No supported algorithms presently.
        ),
    );

    /**
     * Return the part of the conf we got from the database
     *
     * @global m_mysql $db
     * @param string $domain
     * @return array $this->cache_conf_db
     */
    function conf_from_db($domain=false) {
        global $db;
        // Use cache, fill cache if empty
        if (empty($this->cache_conf_db)) {
            $db->query("
        select 
          sd.domaine, 
          replace(replace(dt.entry,'%TARGET%',sd.valeur), '%SUB%', if(length(sd.sub)>0,sd.sub,'@')) as entry 
        from 
          sub_domaines sd,
          domaines_type dt 
        where 
          sd.type=dt.name 
          and sd.enable in ('ENABLE', 'ENABLED') 
        order by entry ;");
            $t=array();
            while ($db->next_record()) {
                $t[$db->f('domaine')][] = $db->f('entry');
            }
            $this->cache_conf_db = $t;
        }
        if ($domain) {
            if (isset($this->cache_conf_db[$domain])) {
                return $this->cache_conf_db[$domain];
            } else {
                return array();
            }
        } // if domain
        return $this->cache_conf_db;
    }


    /**
     * Return full path of the zone configuration file
     * 
     * @param string $domain
     *
     * @param boolean $signed
     *   Whether to return the signed or unsigned zone file path. Ignored
     *   if force is FALSE.
     *
     * @param boolean $force
     *   If FALSE, the zone file path returned will be in accordance with the
     *   configuration for the domain in the database. If forced, the domain
     *   configuratoin will be ignored and the path returned according to the
     *   signed parameter.
     *
     * @return string
     */
    function get_zone_file_uri($domain, $signed = FALSE, $force = FALSE) {
        if (!$force) {
            $d = $this->get_domain_summary($domain);
            $signed = $d['dnssec'];
        }
        if (!$signed) {
            return $this->zone_file_directory.$domain;
        }
        else {
            return "{$this->zone_file_directory}{$domain}.signed";
        }
    }


    /**
     * 
     * @param string $domain
     * @return string zone file path
     */
    function get_zone_file($domain) {
        // Use cache, fill cache if empty
        if (!isset($this->cache_zone_file[$domain]) ) {
            if (file_exists($this->get_zone_file_uri($domain))) {
                $this->cache_zone_file[$domain] = @file_get_contents($this->get_zone_file_uri($domain));
            } else {
                $this->cache_zone_file[$domain] = false;
            }
        }
        return $this->cache_zone_file[$domain] ;
    }


    /**
     * 
     * @param string $domain
     * @return string 
     */
    function get_serial($domain) {
        // Return the next serial the domain must have.
        // Choose between a generated and an incremented.
    
        // Calculated :
        $calc = date('Ymd').'00'."\n";

        // Old one :
        $old=$calc; // default value
        $file = $this->get_zone_file($domain);
        preg_match_all("/\s*(\d{10})\s+\;\sserial\s?/", $file, $output_array);
        if (isset($output_array[1][0]) && !empty($output_array[1][0])) {
            $old = $output_array[1][0];
        }

        // Return max between newly calculated, and old one incremented
        return max(array($calc,$old)) + 1 ;
    }


    /**
     * Return lines that are after ;;; END ALTERNC AUTOGENERATE CONFIGURATION
     * 
     * @param string $domain
     * @return string
     */
    function get_persistent($domain) {
        if ( ! isset($this->cache_get_persistent[$domain] )) {
            preg_match_all('/\;\s*END\sALTERNC\sAUTOGENERATE\sCONFIGURATION(.*)/s', $this->get_zone_file($domain), $output_array);
            if (isset($output_array[1][0]) && !empty($output_array[1][0])) {
                $this->cache_get_persistent[$domain] = $output_array[1][0];
            } else {
                $this->cache_get_persistent[$domain] = false;
            }
        } // isset
        return $this->cache_get_persistent[$domain];
    }
  

    /**
     * 
     * @return string 
     */
    function get_zone_header() {
        return file_get_contents($this->ZONE_TEMPLATE);
    }
  

    /**
     * 
     * @global m_dom $dom
     * @param string $domain
     * @return array Retourne un tableau 
     */
    function get_domain_summary($domain=false) {
        global $dom;

        // Use cache if is filled, if not, fill it
        if (empty($this->cache_domain_summary)) {
            $this->cache_domain_summary = $dom->get_domain_all_summary();
        }

        if ($domain) return $this->cache_domain_summary[$domain];
        else return $this->cache_domain_summary;
    }


    /**
     * 
     * @param string $domain
     * @return boolean
     */
    function dkim_delete($domain) {
        $target_dir = "/etc/opendkim/keys/$domain";
        if (file_exists($target_dir)) {
            @unlink("$target_dir/alternc_private");
            @unlink("$target_dir/alternc.txt");
            @rmdir($target_dir);
        }
        return true;
    }


    /**
     * Generate the domain DKIM key
     * 
     * @param string $domain
     * @return null|boolean
     */
    function dkim_generate_key($domain) {
        // Stop here if we do not manage the mail
        $domainInfo = $this->get_domain_summary($domain);
        if ( !  $domainInfo['gesmx'] ) return;

        $target_dir = "/etc/opendkim/keys/$domain";

        if (file_exists($target_dir.'/alternc.txt')) return; // Do not generate if exist

        if (! is_dir($target_dir)) mkdir($target_dir); // create dir

        // Generate the key
        $old_dir=getcwd();
        chdir($target_dir);
        exec('opendkim-genkey -r -d '.escapeshellarg($domain).' -s "alternc" ');
        chdir($old_dir);

        // opendkim must be owner of the key
        chown("$target_dir/alternc.private", 'opendkim');
        chgrp("$target_dir/alternc.private", 'opendkim');

        return true; // FIXME handle error
    }


    /**
     * Refresh DKIM configuration: be sure to list the domain having a private key (and only them)
     */
    function dkim_refresh_list() { 
        // so ugly... but there is only 1 pass, not 3. Still ugly.
        $trusted_host_new = "# WARNING: this file is auto generated by AlternC.\n# Add your changes after the last line\n";
        $keytable_new     = "# WARNING: this file is auto generated by AlternC.\n# Add your changes after the last line\n";
        $signingtable_new = "# WARNING: this file is auto generated by AlternC.\n# Add your changes after the last line\n";

        # Generate automatic entry
        foreach ($this->get_domain_summary() as $domain => $ds ) {
            // Skip if delete in progress, or if we do not manage dns or mail
            if ( ! $ds['gesdns'] || ! $ds['gesmx'] || strtoupper($ds['dns_action']) == 'DELETE' ) continue;

            // Skip if there is no key generated
            if (! file_exists("/etc/opendkim/keys/$domain/alternc.txt")) continue; 

            // Modif the files.
            $trusted_host_new.="$domain\n";
            $keytable_new    .="alternc._domainkey.$domain $domain:alternc:/etc/opendkim/keys/$domain/alternc.private\n";
            $signingtable_new.="$domain alternc._domainkey.$domain\n";
        }
        $trusted_host_new.="# END AUTOMATIC FILE. ADD YOUR CHANGES AFTER THIS LINE\n";
        $keytable_new    .="# END AUTOMATIC FILE. ADD YOUR CHANGES AFTER THIS LINE\n";
        $signingtable_new.="# END AUTOMATIC FILE. ADD YOUR CHANGES AFTER THIS LINE\n";

        # Get old files
        $trusted_host_old=@file_get_contents($this->dkim_trusted_host_file);
        $keytable_old    =@file_get_contents($this->dkim_keytable_file);
        $signingtable_old=@file_get_contents($this->dkim_signingtable_file);
    
        # Keep manuel entry
        preg_match_all('/\#\s*END\ AUTOMATIC\ FILE\.\ ADD\ YOUR\ CHANGES\ AFTER\ THIS\ LINE(.*)/s', $trusted_host_old, $output_array);
        if (isset($output_array[1][0]) && !empty($output_array[1][0])) {
            $trusted_host_new.=$output_array[1][0];
        } 
        preg_match_all('/\#\s*END\ AUTOMATIC\ FILE\.\ ADD\ YOUR\ CHANGES\ AFTER\ THIS\ LINE(.*)/s', $keytable_old, $output_array);
        if (isset($output_array[1][0]) && !empty($output_array[1][0])) {
            $keytable_new.=$output_array[1][0];
        } 
        preg_match_all('/\#\s*END\ AUTOMATIC\ FILE\.\ ADD\ YOUR\ CHANGES\ AFTER\ THIS\ LINE(.*)/s', $signingtable_old, $output_array);
        if (isset($output_array[1][0]) && !empty($output_array[1][0])) {
            $signingtable_new.=$output_array[1][0];
        } 
    
        // Save if there are some diff
        if ( $trusted_host_new != $trusted_host_old ) {
            file_put_contents($this->dkim_trusted_host_file, $trusted_host_new);
        }
        if ( $keytable_new != $keytable_old ) {
            file_put_contents($this->dkim_keytable_file, $keytable_new);
        }
        if ( $signingtable_new != $signingtable_old ) {
            file_put_contents($this->dkim_signingtable_file, $signingtable_new);
        }

    }

    /**
     * Outputs the include statements for a zone's DnsSec keys if enabled.
     *
     * @param string $domain
     * @returns string
     *   Include statements for all the keys found or an empty ztring.
     */
    function dnssec_entry($domain) {
        $includes = '';
        $key_directory = system_bind::$DNSSEC_KEY_BASEDIR . "/{$domain}";
        $dnssec_enabled = $this->dnssec_is_enabled($domain);
        if ($dnssec_enabled && is_dir($key_directory)) {
            foreach (glob("{$key_directory}/K{$domain}*.key") as $f) {
                if (!is_file($f)) {
                    continue;
                }
                $includes .= "\$INCLUDE {$f}\n";
            }
        }
        return $includes;
    }

    /**
     * Checks if dnssec is enabled for a domain.
     *
     * @param $domain
     *   A string for which domain to check.
     *
     * @returns boolean
     *   True/False if DnsSec is enabled for the domain.
     */
    function dnssec_is_enabled(String $domain) {
        $d = $this->get_domain_summary($domain);
        $enabled = false;
        if ($d && $d['dnssec']) {
            $enabled = true;
        }
        return $enabled;
    }

    /**
     * Signs a zone.
     */
    function dnssec_sign_zone(String $domain) {
        global $msg;
        if (!$domain) {
            return;
        }
        // Keys should already exist.
        $key_dir = system_bind::$DNSSEC_KEY_BASEDIR . "/{$domain}";
        $setfile_dir = system_bind::$DNSSEC_SETFILE_BASEDIR . "/{$domain}";
        if (!is_dir($setfile_dir)) {
            mkdir($setfile_dir, '0750', TRUE);
        }

        $return_code = -1;
        $output = array();
        $salt = _salt16hex();
        if (!$salt) {
            $salt = '-';
        }

        // The unsigned_zone_file should be an absolute path to the zone file.
        // The $INCLUDE statements in the the zone file _MUST_ use absolute
        // paths, otherwise, the CWD of the dnssec-signzone command must be
        // changed.
        $unsigned_zone_file = $this->get_zone_file_uri($domain, FALSE, TRUE);

        // @TODO Should '-Q' and '-R' be used to allow for key roll overs?
        $command = sprintf('/usr/sbin/dnssec-signzone -u -d %s -K %s -3 %s -A -N INCREMENT -o %s %s',
                           escapeshellarg($setfile_dir), escapeshellarg($key_dir),
                           escapeshellarg($salt), escapeshellarg($domain),
                           escapeshellarg($unsigned_zone_file));
        $last_line = exec(escapeshellcmd($command), $output, $return_code);
        $msg->log('system_bind', 'dnssec_sign_zone',
                  sprintf('Signed zone %s using command "%s". Return code %d; Last line of output: %s',
                          $domain, $command, $return_code, $last_line)
        );
        return $return_code;
    }

    /**
     * 
     * @param string $domain
     * @return string
     */
    function dkim_entry($domain) {
        $keyfile="/etc/opendkim/keys/$domain/alternc.txt";
        $domainInfo         = $this->get_domain_summary($domain);
        if (! file_exists($keyfile) &&  $domainInfo['gesmx'] ) {
            $this->dkim_generate_key($domain);
        }
        return @file_get_contents($keyfile);
    }


    /**
     * Conditionnal generation autoconfig entry for outlook / thunderbird
     * If entry with the same name allready exist, skip it.
     * 
     * @param string $domain
     * @return string
     */
    function mail_autoconfig_entry($domain) {
        $zone= implode("\n",$this->conf_from_db($domain))."\n".$this->get_persistent($domain);

        $entry='';
        $domainInfo                 = $this->get_domain_summary($domain);
        if ( $domainInfo['gesmx'] ) {
            // If we manage the mail

            // Check if there is no the same entry (defined or manual)
            // can be toto IN A or toto.fqdn.tld. IN A
            if (! preg_match("/autoconfig(\s|\.".str_replace('.','\.',$domain)."\.)/", $zone )) {
                $entry.="autoconfig IN CNAME %%fqdn%%.\n";
            }
            if (! preg_match("/autodiscover(\s|\.".str_replace('.','\.',$domain)."\.)/", $zone )) {
                $entry.="autodiscover IN CNAME %%fqdn%%.\n";
            }
        } // if gesmx
        return $entry;
    }
  
  
    /**
     * 
     * Return a fully generated zone
     * 
     * @global string $L_FQDN
     * @global string $L_NS1_HOSTNAME
     * @global string $L_NS2_HOSTNAME
     * @global string $L_DEFAULT_MX
     * @global string $L_DEFAULT_SECONDARY_MX
     * @global string $L_PUBLIC_IP
     * @param string $domain
     * @return string
     */
    function get_zone($domain) {
        global $L_FQDN, $L_NS1_HOSTNAME, $L_NS2_HOSTNAME, $L_DEFAULT_MX, $L_DEFAULT_SECONDARY_MX, $L_PUBLIC_IP;

        $zone =$this->get_zone_header();
        $zone.=implode("\n",$this->conf_from_db($domain));
        $zone.="\n;;;HOOKED ENTRY\n";

        $zone.= $this->dkim_entry($domain);
        $zone.= $this->mail_autoconfig_entry($domain);
        $zone .= $this->dnssec_entry($domain);

        $zone.="\n;;; END ALTERNC AUTOGENERATE CONFIGURATION\n";
        $zone.=$this->get_persistent($domain);
        $domainInfo = $this->get_domain_summary($domain);

        // FIXME check those vars
        $zone = strtr($zone, array(
            "%%fqdn%%"=>"$L_FQDN",
            "%%ns1%%"=>"$L_NS1_HOSTNAME",
            "%%ns2%%"=>"$L_NS2_HOSTNAME",
            "%%DEFAULT_MX%%"=>"$L_DEFAULT_MX",
            "%%DEFAULT_SECONDARY_MX%%"=>"$L_DEFAULT_SECONDARY_MX",
            "@@fqdn@@"=>"$L_FQDN",
            "@@ns1@@"=>"$L_NS1_HOSTNAME",
            "@@ns2@@"=>"$L_NS2_HOSTNAME",
            "@@DEFAULT_MX@@"=>"$L_DEFAULT_MX",
            "@@DEFAULT_SECONDARY_MX@@"=>"$L_DEFAULT_SECONDARY_MX",
            "@@DOMAINE@@"=>"$domain",
            "@@SERIAL@@"=>$this->get_serial($domain),
            "@@PUBLIC_IP@@"=>"$L_PUBLIC_IP",
            "@@ZONETTL@@"=> $domainInfo['zonettl'],
        ));

        return $zone;
    }


    /**
     * 
     * @param string $domain
     */
    function reload_zone($domain) {
        exec($this->RNDC." reload ".escapeshellarg($domain), $output, $return_value);
        if ($return_value != 0 ) {
            echo "ERROR: Reload zone failed for zone $domain\n";
        }
    }


    /**
     * return true if zone is locked
     * 
     * @param string $domain
     * @return boolean
     */
    function is_locked($domain) {
        preg_match_all("/(\;\s*LOCKED:YES)/i", $this->get_zone_file($domain), $output_array);
        if (isset($output_array[1][0]) && !empty($output_array[1][0])) {
            return true;
        }
        return false;
    }  


    /**
     * 
     * @global m_mysql $db
     * @global m_dom $dom
     * @param string $domain
     * @return boolean
     */
    function save_zone($domain) {
        global $db, $dom;

        // Do not save if the zone is LOCKED
        if ( $this->is_locked($domain)) {
            $dom->set_dns_result($domain, "The zone file of this domain is locked. Contact your administrator."); // If edit, change dummy_for_translation
            $dom->set_dns_action($domain, 'OK');
            return false;
        }
 
        // Save file, and apply chmod/chown
        // Always want to save the unsigned version.
        $file=$this->get_zone_file_uri($domain, FALSE, TRUE);
        file_put_contents($file, $this->get_zone($domain));
        chown($file, 'bind');
        chmod($file, 0640);
        $d = $this->get_domain_summary($domain);
        if ($d['dnssec']) {
            $this->dnssec_sign_zone($domain);
        }
        // @TODO: What should happen if zone signing fails?
        $dom->set_dns_action($domain, 'OK');
        return true; // fixme add tests
    }


    /**
     * Delete the zone configuration file
     * 
     * @param string $domain
     * @return boolean
     */
    function delete_zone($domain) {
        // get_zone_file_uri() is used since it's result won't be cached.
        $files = array(
            $this->get_zone_file_uri($domain, FALSE, TRUE),
            $this->get_zone_file_uri($domain, TRUE, TRUE),
        );
        foreach ($files as $file) {
            if (file_exists($file)) {
                unlink($file);
            }
        }
        $dnssec_directories = array(
            system_bind::$DNSSEC_KEY_BASEDIR . "/{$domain}",
            system_bind::$DNSSEC_SETFILE_BASEDIR . "/{$domain}",
        );
        foreach ($dnssec_directories as $dir) {
            if ($domain && is_dir($dir)) {
                rmdir($dir);
            }
        }
        $this->dkim_delete($domain);
        return true;
    }


    /**
     * 
     * @global m_hooks $hooks
     * @return boolean
     */
    function reload_named() {
        global $hooks;
        // Generate the new conf file
        $new_named_conf="// DO NOT EDIT\n// This file is generated by Alternc.\n// Every changes you'll make will be overwrited.\n";
        $tpl=file_get_contents($this->NAMED_TEMPLATE);
        foreach ($this->get_domain_summary() as $domain => $ds ) {
            if ( ! $ds['gesdns'] || strtoupper($ds['dns_action']) == 'DELETE' ) continue;
            $new_named_conf.=strtr($tpl, array("@@DOMAINE@@"=>$domain, "@@ZONE_FILE@@"=>$this->get_zone_file_uri($domain)));
        }

        // Get the actual conf file
        $old_named_conf = @file_get_contents($this->NAMED_CONF);

        // Apply new configuration only if there are some differences
        if ($old_named_conf != $new_named_conf ) {
            file_put_contents($this->NAMED_CONF,$new_named_conf);
            chown($this->NAMED_CONF, 'bind');
            chmod($this->NAMED_CONF, 0640);
            exec($this->RNDC." reconfig");
            $hooks->invoke_scripts("/usr/lib/alternc/reload.d", array('dns_reconfig')  );
        }

        return true;
    }


    /**
     * Regenerate bind configuration and load it
     * 
     * @global m_hooks $hooks
     * @param boolean $all
     * @return boolean
     */
    function regenerate_conf($all=false) {
        global $hooks;

        foreach ($this->get_domain_summary() as $domain => $ds ) {
            if ( ! $ds['gesdns'] && strtoupper($ds['dns_action']) == 'OK' ) continue; // Skip if we do not manage DNS and is up-to-date for this domain

            if ( (strtoupper($ds['dns_action']) == 'DELETE' ) || 
            (strtoupper($ds['dns_action']) == 'UPDATE' && $ds['gesdns']==false ) // in case we update the zone to disable DNS management
            ) { 
                $this->delete_zone($domain);
                continue;
            }

            if ( ( $all || strtoupper($ds['dns_action']) == 'UPDATE' ) && $ds['gesdns'] ) {
                $this->save_zone($domain);
                $this->reload_zone($domain);
                $hooks->invoke_scripts("/usr/lib/alternc/reload.d", array('dns_reload_zone', $domain)  );
            }
        } // end foreach domain

        $this->dkim_refresh_list();
        $this->reload_named();
        return true;
    }


    /**
     * 
     */
    private function dummy_for_translation() {
        _("The zone file of this domain is locked. Contact your administrator.");
    }


    /**
     * Returns the current default configuration for dnssec.
     *
     * @returqns array
     *   An array with two indexes 'ksk' (keysigning key), 'zsk' (zonesigning key).
     *   Each key type is also an array with the properities 'algorithm', and 'size'.
     *   Algorithm should match the named parameters for dnssec-keygen, and size should
     *   be an integer.
     */
    public static function default_dnssec_configuration() {
        $data = array(
            'ksk' => array(
                'algorithm' => variable_get('ksk_algorithm', 'RSASHA512', ''),
                'keysize'   => variable_get('ksk_keysize', 2048, ''),
            ),
            'zsk' => array(
                'algorithm' => variable_get('zsk_algorithm', 'RSASHA512', ''),
                'keysize'   => variable_get('zsk_keysize', 2048, ''),
            ),
        );
        return $data;
    }

    /**
     * Returns the DS entries for a domain.
     *
     * @returns string
     *   The output of dnssec-dsfromkey.
     */
    public static function dnssec_ds_entries($domain) {
        return shell_exec("/usr/sbin/dnssec-dsfromkey -A -f {$this->zone_file_directory}/{$domain}");
    }

    /**
     * Creates new key for a domain.
     *
     * @param $domain string
     *   The domain to create the key for.
     *
     * @param $key_type string
     *   One of 'ksk' or 'zsk' for key-sigining keys or zone-sigining keys.
     *
     * @param $algorithm string
     *   The name of algorithm as recognized by dnssec-genkey.
     *
     * @param $length int
     *   The length of the key in bytes. Note: for elliptic curve keys this
     *   parameter is ignored.
     *
     * @returns string|bool
     *   Returns the full path to the keyfile created on success, otherwise FALSE
     *   is returned on a failure.
     */
    public static function dnssec_create_key($domain, $key_type, $algorithm, $length) {
        global $msg;
        $valid = system_bind::validate_key_parameters($key_type, $algorithm, $length);
        if (!$valid) {
            $msg->raise('ERROR', 'system_bind', _("Key generation parameters for {$domain} are invalid. Please check the domain and server default configuration. Type: {$key_type}; Algorithm: {$algorithm}; Key size: {$length}"));
            return FALSE;
        }
        $ksk = '';
        if ($key_type == 'ksk') {
            $ksk = ' -f KSK ';
        }
        $output = array();
        $return_code = -1;
        $key_dir = system_bind::$DNSSEC_KEY_BASEDIR . '/' . $domain;
        // @TODO: This fails because the keys directory is owned and only readable by root.
        // @TODO: Furthermore, this should probably be called during update, when the scripts
        // aren't running as the alterncpanel user.
        // @TODO: Similar problems probably exist for the set files.
        if (!is_dir($key_dir)) {
            if (!mkdir($key_dir, 0750, TRUE)) {
                $msg->raise('ERROR', 'system_bind', _('Unable to create key storage directory'));
                $msg->log('system_bind', 'dnssec_create_key', "Unable to create directory '{$key_dir}'");
                return FALSE;
            }
        }
        $command = sprintf("/usr/sbin/dnssec-keygen -q{$ksk} -a %s -b %s -n ZONE -K %s %s",
                           escapeshellarg($algorithm), escapeshellarg($length),
                           escapeshellarg($key_dir), escapeshellarg($domain));
        $file_name = exec(escapeshellcmd($command), $output, $return_code);
        $msg->log('system_bind', 'dnssec_create_key',
                    sprintf('Executed command "%s". Return code %d ; Last line of output: %s',
                            $command, $return_code, $file_name)
        );
        if ($return_code == 0) {
            return "{$key_dir}/{$file_name}.key";
        }
        else {
            $output = implode("\n", $output);
            $msg->log('system_bind', 'dnssec_create_key', "Full output: {$output}");
        }
        return FALSE;
    }

    public static function validate_key_parameters($key_type, $algorithm, $length) {
        global $msg;
        if (in_array($key_type, array('ksk', 'zsk'))) {
            if (!in_array($algorithm,array_keys(system_bind::$dnssec_key_limits['KSK/ZSK']))) {
                // Unsupported algorithm.
                $msg->debug('system_bind', 'validate_key_parameters',
                            "Key validation failed: unknown algorithm for ksk/zsk {$algorithm}");
                return FALSE;
            }
            $min = system_bind::$dnssec_key_limits['KSK/ZSK'][$algorithm]['min'];
            $max = system_bind::$dnssec_key_limits['KSK/ZSK'][$algorithm]['max'];
            if ($length >=  $min && $length <= $max) {
                if (isset(system_bind::$dnssec_key_limits['KSK/ZSK'][$algorithm]['other'])) {
                    // Only have one "other" check for the moment. Could do more
                    // flexible parsing here.
                    $other = system_bind::$dnssec_key_limits['KSK/ZSK'][$algorithm]['other'];
                    if ($other == '%64') {
                        return $length % 64 == 0;
                    }
                    $msg->debug('system_bind', 'validate_key_parameters',
                                "Key validation failed: unknown other condition '{$other}'");
                }
                else {
                    return TRUE;
                }
            }
            else {
                $msg->debug('system_bind', 'validate_key_parameters',
                            "Key validation failed: keysize ({$length} outside of bounds {$min} and {$max}");
            }
        }
        else {
            $msg->debug('system_bind', 'validate_key_parameters',
                        "Key validation failed: unknown key type '{$key_type}'");
        }
        return FALSE;
    }

    /**
     * Lists all the existing keys for a given domain.
     *
     * @param $domain
     *   The domain name
     *
     * @returns array
     *   An array, possibly empty, of all existing keys for the domain.
     *   The array elements are full paths to the keys.
     */
    public static function list_keys($domain) {
        $r = array();
        if (!$domain) {
            return $r;
        }
       $key_dir = system_bind::$DNSSEC_KEY_BASEDIR . '/' . $domain;
       if (!is_dir($key_dir)) {
           return $r;
       }
       $r = glob("{$key_dir}/K{$domain}*.key");
       return $r;
    }

    /**
     * Gets the timing metadata for a given key.
     *
     * @param $key_file
     *   Full path to the key file.
     *
     * @returns array
     *   An array the metadata properties indexed by name: Created, Publish
     *   Activate, Revoke, Inactive, Delete with the data being NULL (for unset)
     *   or a time in seconds since the UNIX epoch.
     */
    public static function get_key_metadata($key_file) {
        global $msg;
        $data = array();
        if (!is_file($key_file)) {
            return $data;
        }
        $output = shell_exec(escapeshellcmd("LANG=C /usr/sbin/dnssec-settime -u -p all {$key_file}"));
        $lines = explode(PHP_EOL, $output);
        foreach ($lines as $line) {
            $r = explode(": ", $line);
            if ($r && length($r) == 2) {
                $data[$r[0]] = $r[1];
            }
            else {
                $msg->log('system_bind', 'get_key_metadata', "Warning: output line for dnssec-settime for key {$key_file} does not have expected form: \"{$line}\"");
            }
        }
        return $data;
    }

} /* Class system_bind */
