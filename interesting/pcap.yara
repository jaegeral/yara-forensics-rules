/*
   Yara Rule Set
   Author: Alexander Jäger
   Date: 2019-01-07
   Identifier: PCAP
*/

rule pcap_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "PCAP File"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://stackoverflow.com/questions/17928319/whats-the-difference-between-a-pcap-file-with-a-magic-number-of-0x4d3cb2a1-an"
    strings:
        $a = { a1 b2 c3 d4 }
        $b = { 4d 3c b2 a1 }
        $c = { a1 b2 c3 d4 }
        $d = { d4 c3 b2 a1 }
    condition:
       $a at 0 or $b at 0 or $c at 0 or $d at 0
}

rule cap_file
{
	 meta:
        author = "Alexander Jaeger"
        desc = "CAP	Cinco NetXRay, Network General Sniffer, and Network Associates Sniffer capture file"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://wangrui.wordpress.com/2007/06/19/file-signatures-table/"
    strings:
        $a = { 58 43 50 00 }
    condition:
       $a at 0
}
