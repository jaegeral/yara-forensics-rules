/*
   Yara Rule Set
   Author: Alexander Jäger
   Date: 2019-01-07
   Identifier: Various password files
*/

rule pgp_disk_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Windows 95 password file"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        reference = "https://filesignatures.net/index.php?page=search&search=504750644D41494E&mode=SIG"
        version = "v0.1"
        weigth = 80
    strings:
        $a = { 50 47 50 64 4D 41 49 4E }
    condition:
        $a at 0
}