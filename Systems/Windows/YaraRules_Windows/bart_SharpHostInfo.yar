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

rule SharpHostInfo
{
    meta:
        id = "6pYAh7DjfYOnvcl9PJGDjY"
        fingerprint = "v1_sha256_a9973815c925b2c564ef1f4c2d4019e2d7a854d398a2378a0d86e6e4c3feadb4"
        version = "1.0"
        date = "2025-07-24"
        modified = "2025-07-24"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies SharpHostInfo, a tool used for quickly detecting intranet host information and also abused by attackers such as Storm-2603."
        category = "TOOL"
        tool = "SHARPHOSTINFO"
        reference = "https://github.com/shmilylty/SharpHostInfo"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities"
        hash = "d6da885c90a5d1fb88d0a3f0b5d9817a82d5772d5510a0773c80ca581ce2486d"

    strings:
        $str_a = "[!] Failed:"
        $str_b = "[!] Error:"
        $str_c = "manuf.json" fullword
        $str_d = "Detect target:"
        $str_e = "Detect Service:"
        $str_f = "Detect thead:"
        $str_g = "Detect timeout:"
        $str_h = "The parsed detection target is empty"
        $str_i = "An exception occurred while reading the file list!"
        $str_j = "ParsingSocketStremResponse"

        $sharphost = "SharpHostInfo" fullword

    condition:
        8 of ($str_*) or $sharphost
}
