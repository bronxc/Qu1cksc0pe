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

rule EE_Loader
{
    meta:
        id = "3cE9Nc9q8mf33jLJj2u2gN"
        fingerprint = "v1_sha256_8a1f1f3aecfd55da0597ee08795122dbdbea7ad6902b638b8d6e1b73d8ccd5fb"
        version = "1.0"
        date = "2025-10-27"
        modified = "2025-10-27"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies loader used by Earth Estries."
        category = "MALWARE"
        reference = "https://bartblaze.blogspot.com/2025/10/earth-estries-alive-and-kicking.html"
        hash = "5e062fee5b8ff41b7dd0824f0b93467359ad849ecf47312e62c9501b4096ccda"

	strings:
			/*
            pFVar7 = GetProcAddress(pHVar3,(LPCSTR)&local_20);
            if (pFVar7 != (FARPROC)0x0) {
              local_6c = 0x2e534552;
              local_68 = 0x4352;
              local_118c.X = 0;
              local_118c.Y = 0;
              uVar8 = (*local_1194)(0xfffffff5);
              CVar4 = local_118c;
			*/
			$load = { c7 4? ?? 52 45 53 2e 6a f5 c7 4? ?? 52 43 00 00 89 8? ?? ?? ?? ??  } //RES.RC

	condition:
		all of them
}
