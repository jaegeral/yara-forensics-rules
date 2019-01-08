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


rule exchange_mail
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Exchange Email file"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://filesignatures.net/index.php?page=search&search=582D&mode=SIG"
    strings:
        $a = { 58 2D }
    condition:
       $a at 0
}

rule generic_mail_1
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Generic Email file"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://filesignatures.net/index.php?page=search&search=52657475726E2D50&mode=SIG"
    strings:
        $a = { 52 65 74 75 72 6E 2D 50 }
    condition:
       $a at 0
}

rule generic_mail_2
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Generic Email file 2"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://filesignatures.net/index.php?page=search&search=46726F6D&mode=SIG"
    strings:
        $a = { 46 72 6F 6D }
    condition:
       $a at 0
}

rule gpg_pub_keyring
{
	 meta:
        author = "Alexander Jaeger"
        desc = "GPG Public Keyring"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://filesignatures.net/index.php?page=search&search=99&mode=SIG"
    strings:
        $a = { 99 }
        $b = { 99 01 }
    condition:
       $a at 0 or $b at 0
}

rule notes_database
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Lotus Notes Database"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://filesignatures.net/index.php?page=search&search=1A0000040000&mode=SIG"
    strings:
        $a = { 1A 00 00 04 00 00 }
    condition:
       $a at 0
}

rule gpg_secret_keyring
{
	 meta:
        author = "Alexander Jaeger"
        desc = "GPG Secret Keyring"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://filesignatures.net/index.php?page=search&search=9501&mode=SIG"
    strings:
        $a = { 95 01 }
        $b = { 95 00 }
    condition:
       $a at 0 or $b at 0
}

rule outlook_adress_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "Outlook address file"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://filesignatures.net/index.php?page=search&search=9CCBCB8D1375D211&mode=SIG"
    strings:
        $a = { 9C CB CB 8D 13 75 D2 11 }
    condition:
       $a at 0
}

rule vCard
{
	 meta:
        author = "Alexander Jaeger"
        desc = "vCard file"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://filesignatures.net/index.php?page=search&search=424547494E3A5643&mode=SIG"
    strings:
        $a = { 42 45 47 49 4E 3A 56 43 }
    condition:
       $a at 0
}




