/*
   Yara Rule Set
   Author: Alexander Jäger
   Date: 2022-03-31
   Identifier: SQL Dump
*/

rule sql_dump{
	 meta:
        author = "Alexander Jaeger"
        desc = "General SQL dump"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80 
    strings:
        $include1 = "-- MySQL dump" fullword ascii
        $include2 = "DROP TABLE IF EXISTS" fullword ascii
        $include3 = "CREATE TABLE" fullword ascii
        $include4 = "INSERT INTO" fullword ascii
        $exclude1 = "WordPress Administration Scheme API" fullword ascii
        $exclude2 = "WordPress Upgrade API" fullword ascii
        $exclude3 = "<?php" fullword ascii //avoid pgp scripts with schemas
    condition:
        (2 of ($include*)) and not (1 of ($exclude*)) 
}

rule wordpress_sql_dump{
	 meta:
        author = "Alexander Jaeger"
        desc = "Wordpress SQL dump"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80 
    strings:
        $include5 = "wp_posts" fullword ascii
        $include6 = "wp_postmeta" fullword ascii
        $include7 = "wp_usermeta" fullword ascii
        $include8 = "wp_users" fullword ascii
        $exclude1 = "WordPress Administration Scheme API" fullword ascii
    condition:
        (4 of ($include*)) and not (1 of ($exclude*)) 
        and sql_dump
}

rule wordpress_sql_dump_users{
	 meta:
        author = "Alexander Jaeger"
        desc = "Wordpress SQL dump with user details"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80 
    strings:
        $include9 = "INSERT INTO `wp_users` VALUES" fullword ascii
        $exclude1 = "WordPress Administration Scheme API" fullword ascii
    condition:
        (4 of ($include*)) and not (1 of ($exclude*)) and $include9
        and wordpress_sql_dump
}

