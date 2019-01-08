/*
   Yara Rule Set
   Author: Alexander Jäger
   Date: 2019-01-07
   Identifier: Various password files
*/

rule windows_95_password_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Windows 95 password file"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        source = "https://www.garykessler.net/library/file_sigs.html"
        version = "v0.1"
        weigth = 80
    strings:
        $a = { B0 4D 46 43 }
    condition:
        $a at 0
}

rule windows_98_password_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Windows 98 password file"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        source = "https://www.garykessler.net/library/file_sigs.html"
        version = "v0.1"
        weigth = 80
    strings:
        $a = { E3 82 85 96 }
    condition:
        $a at 0
}
