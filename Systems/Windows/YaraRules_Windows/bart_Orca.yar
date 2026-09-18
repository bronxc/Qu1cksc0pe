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

rule Orca_Puppet
{
meta:
	id = "s2PjsAb7LnZvcnL4CcpTL"
	fingerprint = "v1_sha256_f57fd21665cb3e75a5f56b3d3c5eb00d827bf5b5e96cb79f1cb775b300884837"
	version = "1.0"
	date = "2026-01-19"
	modified = "2026-01-19"
	status = "RELEASED"
	sharing = "TLP:CLEAR"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Identifies OrcaC2, a multi-functional C&C framework based on WebSocket encrypted communication."
	category = "MALWARE"
	malware_type = "HACKTOOL"
	reference = "https://github.com/Ptkatz/OrcaC2"
	tool = "ORCAC2"

strings:
	$ = "C:/Users/blood/Desktop/AAA/OrcaC2/"
	$ = "Orca_Puppet/pkg/"
	$ = "Orca_Puppet/cli/"
	$ = "Orca_Puppet/stager"
	$ = "OrcaC2_0H" fullword

condition:
	any of them
}


rule Orca_Stub
{
meta:
	id = "27EhdBiud2OfMZ6utV5eGz"
	fingerprint = "v1_sha256_b331bc0db41c6a16677eb01ee24f59f44e2fd277c33422e16e1ab1ff38597667"
	version = "1.0"
	date = "2026-01-19"
	modified = "2026-01-19"
	status = "RELEASED"
	sharing = "TLP:CLEAR"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Identifies OrcaC2, a multi-functional C&C framework based on WebSocket encrypted communication."
	category = "MALWARE"
	malware_type = "HACKTOOL"
	reference = "https://github.com/Ptkatz/OrcaC2"
	tool = "ORCAC2"

strings:
	$ua = "orca/1.0" fullword
	$pdb_a = "C:\\Users\\blood\\Desktop\\C_Shot\\Release\\C_Shot.pdb"
	$pdb_b = "C:\\Users\\blood\\source\\repos\\Dll1\\Release\\Dll1.pdb"

	$msg_a = "[+] Read %d bytes"
	$msg_b = "[+] Current size: %d, To Read: %d"
	$msg_c = "[+] About to fill buffer"
	$msg_d = "[+] Finished reading file"
	$msg_e = "[-] Error %u in checking bytes left"
	$msg_f = "[-] Error %u in WinHttpReadData."
	$msg_g = "[-] Failed to connect to server"
	$msg_h = "[-] Error %d has occurred."
condition:
	$ua or any of ($pdb_*) or 6 of ($msg_*)
}
