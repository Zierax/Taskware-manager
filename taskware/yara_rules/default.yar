/*
    Taskware Manager — Default YARA Rules (Linux)
    Basic detection rules for common Linux malware patterns.
    Add your own .yar files to this directory for custom scanning.
    
    These rules are intentionally broad for demonstration purposes.
    In production, use more specific rules from threat intelligence feeds.
*/

rule SuspiciousELFStrings
{
    meta:
        description = "Detects common suspicious strings in ELF files"
        author = "Taskware Manager"
        severity = "medium"
        
    strings:
        $s1 = "/bin/sh" ascii
        $s2 = "/bin/bash" ascii
        $s3 = "LD_PRELOAD" ascii
        $s4 = "/dev/tcp/" ascii
        $s5 = "PTRACE_TRACEME" ascii
        $s6 = "PROT_EXEC" ascii
        $s7 = "mprotect" ascii
        $s8 = "system" ascii
        $s9 = "execve" ascii
        
    condition:
        uint32(0) == 0x464C457F and  // ELF magic (\x7fELF)
        4 of ($s*)
}

rule LinuxProcessHiding
{
    meta:
        description = "Detects APIs/strings commonly used to hide processes or files on Linux"
        author = "Taskware Manager"
        severity = "high"
        
    strings:
        $h1 = "hidepid" ascii
        $h2 = "readdir" ascii
        $h3 = "hook" ascii nocase
        $h4 = "kallsyms_lookup_name" ascii
        $h5 = "/proc/" ascii
        $h6 = "dlopen" ascii
        $h7 = "dlsym" ascii
        
    condition:
        uint32(0) == 0x464C457F and
        ($h1 or $h2 or $h4) and
        ($h6 or $h7) and
        $h5
}

rule LinuxReverseShellCradle
{
    meta:
        description = "Detects common Linux reverse shell command patterns"
        author = "Taskware Manager"
        severity = "high"
        
    strings:
        $cmd1 = "nc -e" ascii
        $cmd2 = "ncat -e" ascii
        $cmd3 = "/dev/tcp/" ascii
        $cmd4 = "bash -i" ascii
        $cmd5 = "sh -i" ascii
        $cmd6 = "python -c" ascii
        $cmd7 = "perl -e" ascii
        $cmd8 = "curl -sL" ascii
        $cmd9 = "wget -qO-" ascii
        
    condition:
        2 of ($cmd*)
}

rule SuspiciousPackedELF
{
    meta:
        description = "Detects potentially packed/encrypted ELF binaries"
        author = "Taskware Manager"
        severity = "medium"
        
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
        $ezmdi = "ezmdi" ascii nocase
        $shikata = "shikata" ascii nocase
        
    condition:
        uint32(0) == 0x464C457F and
        any of them
}

rule LinuxAntiDebugging
{
    meta:
        description = "Detects Linux anti-debugging techniques"
        author = "Taskware Manager"
        severity = "medium"
        
    strings:
        $ad1 = "ptrace" ascii
        $ad2 = "PTRACE_TRACEME" ascii
        $ad3 = "WUNTRACED" ascii
        $ad4 = "/proc/self/status" ascii
        $ad5 = "TracerPid" ascii
        $ad6 = "rdtsc" ascii
        
    condition:
        uint32(0) == 0x464C457F and
        3 of ($ad*)
}

rule EICARTestFile
{
    meta:
        description = "EICAR anti-malware test file"
        author = "Taskware Manager"
        severity = "info"
        
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
        
    condition:
        $eicar
}

rule LinuxPersistence
{
    meta:
        description = "Detects Linux persistence techniques"
        author = "Taskware Manager"
        severity = "medium"
        
    strings:
        $p1 = "/etc/crontab" ascii
        $p2 = "/etc/ld.so.preload" ascii
        $p3 = "cron.d" ascii
        $p4 = "rc.local" ascii
        $p5 = "systemd/system" ascii
        $p6 = "init.d" ascii
        $p7 = ".bash_profile" ascii
        $p8 = ".bashrc" ascii
        
    condition:
        uint32(0) == 0x464C457F and
        2 of ($p*)
}

rule CryptoMiner
{
    meta:
        description = "Detects common cryptocurrency miner strings"
        author = "Taskware Manager"
        severity = "high"
        
    strings:
        $m1 = "stratum+tcp" ascii nocase
        $m2 = "stratum+ssl" ascii nocase
        $m3 = "mining.pool" ascii nocase
        $m4 = "xmrig" ascii nocase
        $m5 = "cryptonight" ascii nocase
        $m6 = "hashrate" ascii nocase
        $m7 = "pool_address" ascii nocase
        $m8 = "wallet_address" ascii nocase
        
    condition:
        2 of ($m*)
}
