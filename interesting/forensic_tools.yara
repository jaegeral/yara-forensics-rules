/*
   Yara Rule Set
   Author: Alexander Jäger
   Date: 2019-01-07
   Identifier: Various Forensic Tool detection
*/

rule encase_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Encase Case File"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://filesignatures.net/index.php?page=search&search=5F434153455F&mode=SIG"
    strings:
        $a = { 5F 43 41 53 45 5F }
    condition:
       $a at 0
}
