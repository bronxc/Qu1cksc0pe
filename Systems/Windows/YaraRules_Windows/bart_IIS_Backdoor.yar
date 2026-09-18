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
rule IIS_Backdoor
{
    meta:
        id = "4yJbnKKjfmtotBMpm2zK4F"
        fingerprint = "v1_sha256_4c2d7551e42e643a2265a821c6e629b83cbbbf903afc5ab9577ab13197dd4daa"
        version = "1.0"
        date = "2025-07-24"
        modified = "2025-07-24"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies an IIS backdoor used by Storm-2603."
        category = "TOOL"
        tool = "IISBACKDOOR"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities"
        reference = "https://github.com/WBGlIl/IIS_backdoor"
        hash = "6f6db63ece791c6dc1054f1e1231b5bbcf6c051a49bad0784569271753e24619"

    strings:
        $iis_module = "IHttpModule"
        $str_cmd = "cmd.exe"
        $str_cookie = "sets-cookie"
        $str_dll = "IIS_Server_dll"

        $pdb_part = "\\david8866\\Desktop\\toolsnew\\"
        $pdb_full = "C:\\Users\\david8866\\Desktop\\toolsnew\\backdoor\\IIS-backdoor\\method1-module\\module-backdoor\\IIS-module-cmd\\IIS_Server_dll.pdb"

    condition:
        ($iis_module and 2 of ($str_*)) or
        any of ($pdb_*) or
        dotnet.guids[0]=="05b57f52-968e-4f0f-a3e7-dd0bc7376fc5" or
        dotnet.guids[0]=="3fda4aa9-6fc1-473f-9048-7edc058c4f65"
}
