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

rule RoyalRoad_RTF
{
    meta:
        id = "p1XW7z3B1sdN89zXF7Nel"
        fingerprint = "52be45a991322fa96f4e806cf6fa7a77886f63799c1f67723484bc3796363a4e"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RoyalRoad RTF, used by multiple China-nexus APT groups."
        category = "MALWARE"
        malware = "ROYALROAD"
        malware_type = "EXPLOITKIT"
        reference = "https://nao-sec.org/2020/01/an-overhead-view-of-the-royal-road.html"


    strings:
        $rtf = "{\\rt"
        $RR1 = "5C746D705C382E74" nocase
        $RR2 = "5C417070446174615C4C6F63616C5C54656D705C382E74" nocase

    condition:
        $rtf at 0 and any of ($RR*)
}
