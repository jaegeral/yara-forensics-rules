/*
   Yara Rule Set
   Author: Alexander Jäger
   Date: 2019-01-07
   Identifier: Email
*/

rule pst_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "PST Outlook File"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://asecuritysite.com/forensics/pst"
    strings:
        $a = { 21 42 44 4E 42 }
    condition:
       $a at 0
}

rule msg_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "MSG Email file"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://asecuritysite.com/forensics/msg"
    strings:
        $a = { D0 CF 11 E0 A1 B1 1A E1 }
    condition:
       $a at 0
}


