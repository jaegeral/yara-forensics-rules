
/*
   Yara Rule Set
   Author: Alexander Jäger
   Date: 2019-01-07
   Identifier: Various interesting windows artifacts
*/

rule windows_memory_dump
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Windows memory dump"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        reference = "https://filesignatures.net/index.php?page=search&search=504147454455&mode=SIG"
        version = "v0.1"
        weigth = 80
    strings:
        $a = { 50 41 47 45 44 55 }
    condition:
        $a at 0
}

rule windows_dump_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Windows dump file"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        reference = "https://filesignatures.net/index.php?page=search&search=4D444D5093A7&mode=SIG"
        version = "v0.1"
        weigth = 80
    strings:
        $a = { 4D 44 4D 50 93 A7 }
    condition:
        $a at 0
}

rule windows_event_viewer_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Windows Event Viewer file"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        reference = "https://filesignatures.net/index.php?page=search&search=300000004C664C65&mode=SIG"
        version = "v0.1"
        weigth = 80
    strings:
        $a = { 30 00 00 00 4C 66 4C 65 }
    condition:
        $a at 0
}

rule windows_prefetch_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Windows Event Viewer file"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        reference = "https://filesignatures.net/index.php?page=search&search=1100000053434341&mode=SIG"
        version = "v0.1"
        weigth = 80
    strings:
        $a = { 11 00 00 00 53 43 43 41 }
    condition:
        $a at 0
}


