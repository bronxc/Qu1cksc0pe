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
rule Extract_MachineKey_SharePoint
{
    meta:
        id = "5rgC2cpznLmamBSQ9etlFh"
        fingerprint = "v1_sha256_267976231782f0458c369172e8d922508daf670089ef3c91ad2570fe3600d6c4"
        version = "1.0"
        date = "2025-07-25"
        modified = "2025-07-25"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies webshell that extracts SharePoint's MachineKey configuration."
        category = "TOOL"
        tool = "WEBSHELL"
        reference = "https://x.com/Gi7w0rm/status/1948027800591466773"
        hash = "3461da3a2ddcced4a00f87dcd7650af48f97998a3ac9ca649d7ef3b7332bd997"

    strings:
        $xml = "<?xml" nocase

        $httpcontext = "HttpContext" fullword
        $validation = "MachineKeyValidation"

        $mks_a = "MachineKeySection"
        $mks_b = "System.Web.Configuration.MachineKeySection"

        $str_a = "-------------------- .NET Properties --------------------"
        $str_b = "Number of Logical Drives:"
        $str_c = "List of Logical Drives:"
        $str_d = "Computer Name:"
        $str_e = "Full path of the system directory:"
        $str_f = "Current Directory:"
        $str_g = "Number of processors on this machine:"
        $str_h = "Number of milliseconds since system start:"
        $str_i = "Username of the user currently logged onto the operating system:"
        $str_j = "Operating System Version:"
        $str_k = ".NET Version:"
        $str_l = "-------------------- Environment Variables --------------------"

    condition:
        not $xml in (0..10) and (
        ($httpcontext and $validation and any of ($mks_*)) or (any of ($mks_*, $validation) and 8 of ($str_*)) or
        dotnet.guids[0]=="64c708ee-5f26-4eef-b474-651321a0e469" or
        dotnet.guids[0]=="a253a3d9-f7e6-484e-b392-685b0b7a9c5d" or
        dotnet.guids[0]=="ab423cff-901e-4882-9939-bf1b54eddffb" or
        dotnet.guids[0]=="63e8005d-08a3-423d-ab6b-53cc05629d457" or
        dotnet.guids[0]=="de37ec6b-4312-4073-81ea-903f0a340a11"
		)
}
