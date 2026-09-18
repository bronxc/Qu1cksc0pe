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

rule Unk_Mythic_Loader
{
meta:
	id = "14BIyhtqgQCTCfLjhUU27p"
	fingerprint = "v1_sha256_30aabd24914ecbce0404d81427b6c6f2f6c5d92c342070da2cab90ed01bc754b"
	version = "1.0"
	date = "2026-01-27"
	modified = "2026-01-27"
	status = "RELEASED"
	sharing = "TLP:CLEAR"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Identifies an unknown loader for Mythic C2, likely redteam or APT."
	category = "MALWARE"
	malware_type = "LOADER"
	hash = "e7e4eee2bed7f472c0cd753f13bee3d2d3eefa7e055374d7fcd89049e836119e"

strings:
	$ = "[-] Error in NTWVM_4"
	$ = "[-] Error in NTWVM_3"
	$ = "[-] Error in NTWVM_2"
	$ = "[-] Error in NTWVM_1"
	$ = "[-] Error in NTAVM: "
	$ = "[-] Unable to get NNSsrc\\syscall.rs"
	$ = "[-] NT headers do not match signature with from dll base"
	$ = "[-] DOS header not matched from base address"
	$ = "[-] Error in NTWVM_4"
	$ = "[-] Unable to get NNS"
	$ = "[+] Found the PEB and the InMemoryOrderModuleList at"
	$ = "[+] Module address:"
	$ = "[+] DOS header matched"
	$ = "[+] NT headers matched"
	$ = "[+] Function name found"

condition:
	8 of them
}
