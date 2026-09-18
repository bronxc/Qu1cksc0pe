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

rule Autumn_Backdoor
{
    meta:
        id = "2kQ17alOYwTwkkTNA8vZCX"
        fingerprint = "v1_sha256_7a32b90fb6e962a82af808d698dc19d503c075606f5a7e52f783f0c7d71f5936"
        version = "2.0"
        date = "2025-09-26"
        modified = "2025-11-18"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies backdoored libcef.dll (stage 1), used by a China-nexus APT, as seen in the Autumn Dragon report."
        category = "MALWARE"
        malware = "UNKNOWN"
        malware_type = "BACKDOOR"
        reference = "https://cyberarmor.tech/blog/autumn-dragon-china-nexus-apt-group-targets-south-east-asia"
        hash = "a3805b24b66646c0cf7ca9abad502fe15b33b53e56a04489cfb64a238616a7bf"

    strings:
        $s1 = "Could not get process list."
        $s2 = "Please send the document now."
        $s3 = "Failed to create pipe."
        $s4 = "Failed to start process."
        $s5 = "Command executed but returned no output."
		$s6 = "Screenshot taken."
		$s7 = "Please send a document, not text."

        $x1 = "No file or photo found in message."
        $x2 = "Error: Cannot create file on disk."
        $x3 = "File saved to: "
        $x4 = "Error receiving file:"

    condition:
        4 of ($s*) or 3 of ($x*)
}
