/*
   Yara Rule Set
   Author: Alexander Jäger
   Date: 2019-01-07
   Identifier: 1Password
*/

rule OnePassword_Emergency_Kit_file{
	 meta:
        author = "Alexander Jaeger"
        desc = "1Password Emergency Kit File"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80 
    strings:
        $a = "OnePasswordURL" fullword ascii
        $b = "onepassword://" fullword ascii
        $c = "Producer (PDFKit)" fullword ascii
    condition:
        all of them
}

rule OnePassword_1Password_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "1Password File"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80 
    strings:
        $a = "uuid" fullword ascii
        $b = "encrypted" fullword ascii
        $c = "createdAt" fullword ascii
        $d = "typeName" fullword ascii
	    $e = "txTimestamp" fullword ascii
    condition:
        all of them
}
