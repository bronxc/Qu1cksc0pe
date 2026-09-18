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

rule Pulsar_RAT
{
meta:
	id = "3t0qvuhxPyAAjAGoxh0hzU"
	fingerprint = "v1_sha256_dd4e87f5677cd6a275cbd3f985b25776a040a3f69079877a709477500b6dc4ad"
	version = "1.0"
	date = "2026-01-22"
	modified = "2026-01-22"
	status = "RELEASED"
	sharing = "TLP:CLEAR"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Identifies Pulsar RAT, based on Quasar RAT."
	category = "MALWARE"
	malware_type = "RAT"
	reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pulsar_rat"

strings:
	$ = "costura.pulsar"
	$ = "Pulsar.Common"
	$ = "Pulsar.Client"
	$ = "Pulsar Client" ascii wide
	$ = "Pulsar HVNC Progress UI" ascii wide
	$ = "PulsarDesktop" ascii wide
	$ = "PulsarMessagePackSerializer"

condition:
	2 of them
}
