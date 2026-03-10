/*
    Taskware Manager - Linux Hacktools & Post-Exploitation
    Detects privilege escalation scripts, proxies, shells, and Cobalt Strike.
*/

rule Linux_Hacktool_LinPEAS
{
    meta:
        description = "Detects LinPEAS privilege escalation script"
        author = "Taskware Manager"
        severity = "high"
        
    strings:
        $s1 = "linpeas" ascii nocase
        $s2 = "Linux Privilege Escalation Awesome Script" ascii
        $s3 = "https://github.com/carlospolop/PEASS-ng" ascii
        $s4 = "BASIC SYSTEM INFO" ascii
        $s5 = "USER INFORMATION" ascii
        
    condition:
        2 of ($s*)
}

rule Linux_Hacktool_Chisel
{
    meta:
        description = "Detects Chisel TCP/UDP tunnel over HTTP"
        author = "Taskware Manager"
        severity = "high"
        
    strings:
        $s1 = "github.com/jpillora/chisel" ascii
        $s2 = "chisel server" ascii
        $s3 = "chisel client" ascii
        $s4 = "Fast TCP/UDP tunnel over HTTP" ascii
        
    condition:
        uint32(0) == 0x464C457F and 
        2 of ($s*)
}

rule Linux_CobaltStrike_Beacon
{
    meta:
        description = "Detects Cobalt Strike Linux Beacon"
        author = "Taskware Manager"
        severity = "critical"
        
    strings:
        $s1 = "beacon" ascii fullword
        $s2 = "beacon.x64" ascii 
        $s3 = "beacon.x86" ascii
        $s4 = "sleep_mask" ascii
        $s5 = "postex" ascii
        $s6 = "pivot" ascii
        
    condition:
        uint32(0) == 0x464C457F and
        3 of ($s*)
}

rule Linux_ReverseShell_ELF
{
    meta:
        description = "Detects compiled reverse shell binaries"
        author = "Taskware Manager"
        severity = "high"
        
    strings:
        $s1 = "socket" ascii fullword
        $s2 = "connect" ascii fullword
        $s3 = "dup2" ascii fullword
        $s4 = "execve" ascii fullword
        $s5 = "fork" ascii fullword
        $s6 = "/bin/sh" ascii
        $s7 = "/bin/bash" ascii
        
    condition:
        uint32(0) == 0x464C457F and
        $s1 and $s2 and $s3 and $s4 and ($s6 or $s7)
}
