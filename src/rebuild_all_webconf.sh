#!/bin/bash

# Get some vars
. /usr/lib/alternc/functions.sh

echo "This script will rebuild all web configuration and regenerate DNS."
echo ""
echo "Only files in $VHOST_MANUALCONF will be preserved."
echo "Use --force to skip confirmation"
echo ""

if [ ! "$1" == "--force" ] ; then 
  read -n1 -p "Continue (y/n)? "
  [[ $REPLY = [yY] ]] ||  exit 1
fi

echo ""
echo "++ Start rebuilding ++"

echo "Set flag to rebuild"
mysql_query "update sub_domaines set web_action = 'UPDATE' and web_action != 'DELETE';"
mysql_query "update     domaines set dns_action = 'UPDATE' and dns_action != 'DELETE';"

echo "Launch update_domains to rebuild."
/usr/lib/alternc/update_domains.sh
/usr/lib/alternc/generate_bind_conf.php --force

echo "Finish."

