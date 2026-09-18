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
rule EE_Dropper
{
    meta:
        id = "25d2Jqee4Uip3sr0muPuRO"
        fingerprint = "v1_sha256_8c095876a8282857f9434e97fce844d79e4dd8994a9dc61d2be3fce8f6dcb6d1"
        version = "1.0"
        date = "2025-10-27"
        modified = "2025-10-27"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies dropper, EXE dropping and loading 3 CAB files, as seen in Earth Estries campaign."
        category = "MALWARE"
        reference = "https://bartblaze.blogspot.com/2025/10/earth-estries-alive-and-kicking.html"
        hash = "3822207529127eb7bdf2abc41073f6bbe4cd6e9b95d78b6d7dd04f42d643d2c3"

	strings:
		$cab = {4D 53 43 46} //MSCF

	condition:
		uint16(0) == 0x5A4D and
		#cab == 3 and
		(
			for any i in (0 .. pe.number_of_resources - 1): (
				pe.resources[i].type_string == "T\x00E\x00S\x00T\x00"
			)
		)
}
