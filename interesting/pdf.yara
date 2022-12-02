/*
   Yara Rule Set
   Author: Alexander Jäger
   Date: 2019-01-07
   Identifier: PDF
*/

rule confidential_pdf
{
    meta:
        description = "Detects PDF files containing confidential words"
        author = "Alexander Jaeger"
        desc = "Detects PDF files containing confidential words"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80 
        date = 2022-12-02

    strings:
        $magic = {25 50 44 46} // magic number for the PDF file format
        $keyword1 = "confidential"
        $keyword2 = "secret"
        $keyword3 = "need to know"
        $keyword4 = "ntk"

    condition:
        $magic at 0 and ($keyword1 in (0..1024) or $keyword2 in (0..1024) or $keyword3 in (0..1024) or $keyword4 in (0..1024))
}
