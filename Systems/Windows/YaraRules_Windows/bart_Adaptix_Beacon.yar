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

rule Adaptix_Beacon
{
    meta:
        id = "1ZkQQJeaX6cNWZ9NA92MVp"
        fingerprint = "v1_sha256_3e65f762c253b42a97dd34e0904aa561b4413685e65b73fc28b2ac326a379722"
        version = "1.0"
        date = "2025-11-20"
        modified = "2025-11-20"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Adaptix beacon."
        category = "MALWARE"
        malware_type = "HACKTOOL"
        tool = "ADAPTIX"
        reference = "https://github.com/Adaptix-Framework/AdaptixC2"

    strings:
        $coffer = "coffer.Load"

        $func_TaskProcess = "main.TaskProcess"
        $func_jobDownloadStart = "main.jobDownloadStart"
        $func_jobRun = "main.jobRun"
        $func_jobTerminal = "main.jobTerminal"
        $func_jobTunnel = "main.jobTunnel"
        $func_taskCat = "main.taskCat"
        $func_taskCd = "main.taskCd"
        $func_taskCp = "main.taskCp"
        $func_taskExecBof = "main.taskExecBof"
        $func_taskExit = "main.taskExit"
        $func_taskJobKill = "main.taskJobKill"
        $func_taskJobList = "main.taskJobList"
        $func_taskKill = "main.taskKill"
        $func_taskLs = "main.taskLs"
        $func_taskMkdir = "main.taskMkdir"
        $func_taskMv = "main.taskMv"
        $func_taskPs = "main.taskPs"
        $func_taskPwd = "main.taskPwd"
        $func_taskRm = "main.taskRm"
        $func_taskScreenshot = "main.taskScreenshot"
        $func_taskShell = "main.taskShell"
        $func_taskTerminalKill = "main.taskTerminalKill"
        $func_taskTunnelKill = "main.taskTunnelKill"
        $func_taskUpload = "main.taskUpload"
        $func_taskZip = "main.taskZip"

    condition:
        ( $coffer and 5 of ($func_*) ) or
        15 of ($func_*)
}
