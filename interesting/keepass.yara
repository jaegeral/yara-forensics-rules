/*
   Yara Rule Set
   Author: Alexander Jäger
   Date: 2019-01-07
   Identifier: Keepass
*/

rule Keepass_csv_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Keepass CSV File"
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
