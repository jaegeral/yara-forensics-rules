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
        $a = "BEGIN PRIVATE KEY" fullword ascii
        $b = "RSA private key" fullword ascii
        $c = "OpenSSH private key" fullword ascii
        $d = "BEGIN OPENSSH PRIVATE KEY" fullword ascii
    condition:
        1 of them
}

