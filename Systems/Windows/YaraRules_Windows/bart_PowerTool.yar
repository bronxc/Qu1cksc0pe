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

import "pe"

rule PowerTool
{
    meta:
        id = "1xsVS7M8rwYUf81xA2UjIE"
        fingerprint = "0244bd12a172270bedd0165ea5fd95ee4176e46a0fb501e0888281927fbbea4b"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2025-07-24"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PowerTool, sometimes used by attackers to disable security software."
        category = "TOOL"
        tool = "POWERTOOL"
        reference = "https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml"


    strings:
        $ = "C:\\dev\\pt64_en\\Release\\PowerTool.pdb"
        $ = "Detection may be stuck, First confirm whether the device hijack in [Disk trace]" ascii wide
        $ = "SuspiciousDevice Error reading MBR(Kernel Mode) !" ascii wide
        $ = "Modify kill process Bug." ascii wide
        $ = "Chage language nedd to restart PowerTool" ascii wide
        $ = ".?AVCPowerToolApp@@" ascii wide
        $ = ".?AVCPowerToolDlg@@" ascii wide

    condition:
        any of them
}
