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

import "dotnet"
rule SharpAdidnsdump
{
    meta:
        id = "6rWYf0SwQzWanysjEs2F3h"
        fingerprint = "v1_sha256_81a0841b64b31da7c8e6f601913eaabbcf2d03868c46b6d5acf2da532964c200"
        version = "1.0"
        date = "2025-07-24"
        modified = "2025-07-24"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies SharpAdidnsdump, which allows for AD integrated DNS dumping and also abused by attackers such as Storm-2603."
        category = "TOOL"
        tool = "SHARPAPIDNSDUMP"
        reference = "https://github.com/b4rtik/SharpAdidnsdump"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities"
        hash = "f01675f9ca00da067bdb1812bf829f09ccf5658b87d3326d6fddd773df352574"

    strings:
        $str_a = "IPAddress"
        $str_b = "DirectorySearcher"
        $str_c = "SearchResult"
        $str_d = "IPHostEntry"
        $str_e = "GetHostEntry"
        $str_f = "DirectoryEntry"

        $clear_a = "Error retriving data"
        $clear_b = "dNSTombstoned"
        $clear_c = "Running enumeration against"

        $SharpAdidnsdump = "SharpAdidnsdump" fullword

    condition:
        (3 of ($str_*) and any of ($clear_*)) or
        $SharpAdidnsdump or
        dotnet.guids[0]=="8f985494-906c-485c-b3b3-0e90aa7d3ca7"
}
