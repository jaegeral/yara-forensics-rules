/*
   Yara Rule Set
   Author: Alexander Jäger
   Date: 2019-01-07
   Identifier: Keepass
*/

rule Keepass_xml_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Keepass File Format: CSV (KeePass 1.x)"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80 
        reference = "https://keepass.info/help/base/importexport.html#csv"
    strings:
        $a = "<pwlist>"
        $b = "<pwentry>"
        $c = "<username>"
        $d = "<lastaccesstime>"
        $e = "</group>"
        $f = "</pwentry>"
    condition:
        all of them
}


rule Keepass_csv_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Keepass File Format: XML (KeePass 1.x)"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://keepass.info/help/base/importexport.html#xml"
    strings:
        $a = "Account" fullword ascii
        $b = "Login Name" fullword ascii
        $c = "Password" fullword ascii
        $d = "Web Site" fullword ascii
        $e = "Comments" fullword ascii
    condition:
        all of them
}


