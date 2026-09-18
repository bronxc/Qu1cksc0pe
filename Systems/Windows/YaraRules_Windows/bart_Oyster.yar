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

rule Oyster
{
    meta:
        id = "7kE7GnnyOPX7qw3Kwwua0X"
        fingerprint = "v1_sha256_c635149f6091ca338956c8c7639aeeab30d70456e06e5d894a1bef0a1c0a031a"
        version = "1.0"
        date = "2025-09-26"
        modified = "2025-09-26"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Oyster aka Broomstick aka CleanUp backdoor."
        category = "MALWARE"
        malware = "OYSTER"
        malware_type = "BACKDOOR"
        reference = "https://x.com/roo7cause/status/1971453273862176887"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.broomstick"
        hash = "169157f51c05aafda68eb367219a826ecdc90e941e4397da20021b0f4ee2ae14"

    strings:
        $ = "WordPressAgent" fullword
        $ = "FingerPrint" fullword
        $ = "TimeSleep: %d"
        $ = "[CountStartupProcessSystem] EnumProcesses failed"
        $ = "Fail Find End .ICO File"
        $ = "Fail Find DLL File Round 2"
        $ = "Mutex already exists, another instance is running."
        $ = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q"
        $ = "The installation has not been completed successfully. We kindly ask you to try again later."

    condition:
        6 of them
}
