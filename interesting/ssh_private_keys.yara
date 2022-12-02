/*
   Yara Rule Set
   Author: Alexander Jäger
   Date: 2022-03-31
   Identifier: SSH
*/

rule ssh_private_key{
	meta:
        author = "Alexander Jaeger"
        desc = "SSH private key file"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80 
    strings:
        $magic1 = {2D 2D 2D 2D 2D 42 45 47 49 4E 2D 2D 2D 2D 2D}
        $magic2 = {2D 2D 2D 2D 2D 42 45 47 49 4E 20 50 52 49 56}
        $type1 = "BEGIN PRIVATE KEY" fullword ascii
        $type2 = "RSA private key" fullword ascii
        $type3 = "OpenSSH private key" fullword ascii
        $type4 = "OPENSSH PRIVATE KEY" fullword ascii
	$type5 = "EC PRIVATE KEY" fullword ascii
    condition:
        ($magic1 at 0 or $magic2 at 0) and ($type1 in (0..1024) or $type2 in (0..1024) or $type3 in (0..1024) or $type4 in (0..1024) or $type5 in (0..1024) 
}

