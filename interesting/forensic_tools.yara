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

rule access_data_ftk_evidence
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Access Data FTK evidence"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://filesignatures.net/index.php?page=search&search=A90D000000000000&mode=SIG"
    strings:
        $a = { A9 0D 00 00 00 00 00 00 }
    condition:
       $a at 0
}

rule evf_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Expert Witness Compression Format"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://filesignatures.net/index.php?page=search&search=455646090D0AFF00&mode=SIG"
    strings:
        $a = { 45 56 46 09 0D 0A FF 00 }
    condition:
       $a at 0
}


