/*
   Yara Rule Set
   Author: Alexander Jäger
   Date: 2019-01-07
   Identifier: 1Password_Emergency_Kit_File
*/

rule OnePassword_Emergency_Kit_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "1Password Emergency Kit File"
        version = "v0.1"
        weigth = 80 
    strings:
        $a = "OnePasswordURL"
        $b = "onepassword://"
        $c = "Producer (PDFKit)"
    condition:
        all of them
}
