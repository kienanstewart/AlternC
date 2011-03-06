-- Alter table to allow use of ipv6, cname and txt in dns record
ALTER TABLE sub_domaines DROP PRIMARY KEY;
ALTER TABLE sub_domaines ADD CONSTRAINT pk_SubDomaines PRIMARY KEY (compte,domaine,sub,type,valeur);

-- Alter table mail_domain to add support of temporary mail
ALTER TABLE mail_domain ADD expiration_date datetime DEFAULT null;

-- Domains type
CREATE TABLE IF NOT EXISTS `domaines_type` (
    `name` VARCHAR (255) NOT NULL, -- Uniq name
    `description` TEXT, -- Human description
    `target` enum ('NONE', 'URL', 'DIRECTORY', 'IP', 'IPV6', 'DOMAIN', 'TXT') NOT NULL DEFAULT 'NONE', -- Target type
    `entry` VARCHAR (255) DEFAULT '', -- BIND entry
    `compatibility` VARCHAR (255) DEFAULT '', -- Which type can be on the same subdomains
    `enable` enum ('ALL', 'NONE', 'ADMIN') NOT NULL DEFAULT 'ALL', -- Show this option to who ?
    `only_dns` BOOLEAN DEFAULT FALSE, -- Update_domains modify just the dns, no web configuration
    `need_dns` BOOLEAN DEFAULT TRUE, -- The server need to be the DNS to allow this service
    `advanced` BOOLEAN DEFAULT TRUE, -- It's an advanced option
PRIMARY KEY ( `name` )
) COMMENT = 'Type of domains allowed';

INSERT IGNORE INTO `domaines_type` (name, description, target, entry, compatibility, only_dns, need_dns, advanced) values
('vhost','Locally managed', 'DIRECTORY', '%SUB% IN A @@PUBLIC_IP@@', 'txt', false, false, false),
('url','URL redirection', 'URL', '%SUB% IN A @@PUBLIC_IP@@','txt', true, true, false),
('ip','IP redirection', 'IP', '%SUB% IN A %TARGET%','url,ip,ipv6,txt', false, true, true),
('webmail', 'Webmail access', 'NONE', '%SUB% IN A @@PUBLIC_IP@@', 'txt', false, false, false),
('ipv6','IPv6 address', 'IPV6', '%SUB% IN AAAA %TARGET%','ip,ipv6,webmail,txt',true, true, true ),
('cname', 'cname entry', 'DOMAIN', '%SUB% CNAME %TARGET%', 'txt',true, true, true ),
('txt', 'txt entry', 'TXT', '%SUB% IN TXT "%TARGET%"','vhost,url,ip,webmail,ipv6,cname,txt',true, true, true),
('mx', 'mx entry', 'IP', '%SUB% IN MX %TARGET%', 'vhost,url,ip,webmail,ipv6,cname,txt',true, false, true),
('panel', 'Panel redirection', 'NONE', '%SUB% IN A @@PUBLIC_IP@@', 'vhost,url,ip,webmail,ipv6,cname,txt',true, false, false)
;

-- Changing standby use
alter table domaines add column dns_action enum ('OK','UPDATE','DELETE') NOT NULL default 'UPDATE';
alter table domaines add column dns_result varchar(255) not null default '';
alter table sub_domaines add column web_action enum ('OK','UPDATE','DELETE') NOT NULL default 'UPDATE';
alter table sub_domaines add column web_result varchar(255) not null default '';
alter table sub_domaines add column enable enum ('ENABLED', 'ENABLE', 'DISABLED', 'DISABLE') NOT NULL DEFAULT 'ENABLED';
drop table sub_domaines_standby;
drop table domaines_standby;

update sub_domaines set type='VHOST' where type='0'; -- We decide to drop massvhost.
update sub_domaines set type='URL' where type='1';
update sub_domaines set type='IP' where type='2';
update sub_domaines set type='WEBMAIL' where type='3';
update sub_domaines set type='IPV6' where type='4';
update sub_domaines set type='CNAME' where type='5';
update sub_domaines set type='TXT' where type='6';
update sub_domaines set web_action='UPDATE';

