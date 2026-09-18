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

rule StormDNS
{
    meta:
        id = "75nX2TPCk53RAhU55yBeFd"
        fingerprint = "v1_sha256_542a8af37bd4bc18218190cd82495146a4daa5d01db24804b9ff16ff04023a5a"
        version = "1.0"
        date = "2025-07-24"
        modified = "2025-07-24"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies StormDNS, a DNS shell used by Storm-260 to receive and execute commands from a C2."
        category = "MALWARE"
        malware = "STORMDNS"
        malware_type = "WEBSHELL"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities"
        hash = "1eb914c09c873f0a7bcf81475ab0f6bdfaccc6b63bf7e5f2dbf19295106af192"

    strings:
        $str_a = "Slept for %d seconds"
        $str_b = "Failed to allocate memory"
        $str_c = "cmd.exe /c %s 2>&1"
        $str_d = "Failed to execute command"
        $str_e = "Failed to reallocate memory"
        $str_f = "Command executed with no output"
        $str_g = "fragment_received"
        $str_h = "result_received"
        $str_i = "s%st%04zup%04zu"

        $pdb_part = "\\work\\tools\\ak47c2\\"
        $pdb_full = "C:\\Users\\Administrator\\Desktop\\work\\tools\\ak47c2\\dnsclinet-c\\dnsclient\\x64\\Release\\dnsclient.pdb"

    condition:
        8 of ($str_*) or any of ($pdb_*)
}
