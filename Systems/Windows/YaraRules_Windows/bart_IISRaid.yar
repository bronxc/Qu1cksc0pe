/*
Upstream license notice (applies to this rule file):

MIT License

Copyright (c) 2020 Bart

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

rule IISRaid
{
    meta:
        id = "40tj9tn6FNrr4xE042IPIm"
        fingerprint = "521b0798e25a620534f8e04c8fd62fd42c90ea5b785968806cb7538986dedac6"
        version = "1.0"
        creation_date = "2021-08-01"
        first_imported = "2021-12-30"
        last_modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies IISRaid."
        category = "MALWARE"
        malware = "IISRAID"
        malware_type = "BACKDOOR"
        reference = "https://github.com/0x09AL/IIS-Raid"


    strings:
        $pdb1 = "\\IIS-Raid-master\\" ascii wide
        $pdb2 = "\\IIS-Backdoor.pdb"
        $s1 = "C:\\Windows\\System32\\credwiz.exe" ascii wide
        $s2 = "C:\\Windows\\Temp\\creds.db" ascii wide
        $s3 = "CHttpModule::" ascii wide
        $s4 = "%02d/%02d/%04d %02d:%02d:%02d | %s" ascii wide

    condition:
        any of ($pdb*) or 3 of ($s*)
}