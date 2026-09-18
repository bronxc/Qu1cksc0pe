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

rule Warlock
{
    meta:
        id = "4jggrARzQ2bsxiH62DEQRz"
        fingerprint = "v1_sha256_bae361b7df9cc56f933d73b72104c43f766f964dedd05603acc1249b23e1de6f"
        version = "1.0"
        date = "2025-07-24"
        modified = "2025-07-24"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Warlock ransomware used by Storm-2603. It is also known as x2anylock ransomware and is a Lockbit (Black) derivative."
        category = "MALWARE"
        malware = "WARLOCK"
        malware_type = "RANSOMWARE"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities"
        hash = "abb0fa128d3a75e69b59fe0391c1158eb84a799ddb0abc55d2d6be3511ef0ea1"

    strings:
        $str_pw = "replacethispassword" fullword
        $str_id = "Your decrypt ID:"
        $str_qtox = "QTox ID Support:"
        $str_email = "Email Support:"
        $str_contact = "You can contact us in email or qtox."
        $str_decrypt = "How to decrypt my data.log"

        $ext = ".x2anylock" fullword
        $pdb_part_work = "\\work\\tools\\ai\\ak47\\"
        $pdb_part_end = "\\My7zdllhijacked.pdb"
        $pdb_full = "C:\\Users\\Administrator\\Desktop\\work\\tools\\ai\\ak47\\cpp\\7zdllhijacked\\7zdllhijacked\\x64\\Release\\My7zdllhijacked.pdb"

    condition:
        5 of ($str_*) or $ext or any of ($pdb_*)
}
