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

rule XiaoBa
{
    meta:
        id = "7HQbk7TyDS3DhwWOktZe9t"
        fingerprint = "d41a019709801bbbc4284b27fd7f582ed1db624415cb28b88a7cdf5b0c3331b2"
        version = "2.0"
        creation_date = "2019-09-01"
        first_imported = "2021-12-30"
        last_modified = "2025-09-29"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies XiaoBa ransomware unpacked or in memory."
        category = "MALWARE"
        malware = "XIAOBA"
        malware_type = "RANSOMWARE"

    strings:
        $ = "BY:TIANGE" ascii wide
        $ = "Your disk have a lock" ascii wide
        $ = "Please enter the unlock password" ascii wide
        $ = "Please input the unlock password" ascii wide
        $ = "I am very sorry that all your files have been encrypted" ascii wide

    condition:
        2 of them
}
