/*
   Yara Rule Set
   Author: Alexander Jäger
   Date: 2019-01-07
   Identifier: VMDK
*/

rule vmdk_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "VMDK File"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://en.wikipedia.org/wiki/List_of_file_signatures"
    strings:
        $a = { 4B 44 4D }
    condition:
       $a at 0
}
