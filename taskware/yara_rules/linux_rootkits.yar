/*
    Taskware Manager - Linux Rootkits and Ransomware
    Detects LKM rootkits (Diamorphine, Reptile) and Ransomware (Linux.Encoder).
*/

rule Linux_Rootkit_Diamorphine
{
    meta:
        description = "Detects Diamorphine LKM rootkit artifacts"
        author = "Taskware Manager"
        severity = "critical"
        
    strings:
        $s1 = "diamorphine" ascii nocase
        $s2 = "diamorphine_init" ascii
        $s3 = "diamorphine_cleanup" ascii
        $s4 = "hacked_getdents" ascii
        $s5 = "hacked_kill" ascii
        
    condition:
        uint32(0) == 0x464C457F and
        3 of ($s*)
}

rule Linux_Rootkit_Reptile
{
    meta:
        description = "Detects Reptile LKM rootkit artifacts"
        author = "Taskware Manager"
        severity = "critical"
        
    strings:
        $s1 = "reptile" ascii nocase
        $s2 = "reptile_init" ascii
        $s3 = "reptile_exit" ascii
        $s4 = "reptile_hide_proc" ascii
        $s5 = "hacked_tcp4_seq_show" ascii
        
    condition:
        uint32(0) == 0x464C457F and
        3 of ($s*)
}

rule Linux_Ransomware_Generic
{
    meta:
        description = "Detects generic Linux ransomware behaviors"
        author = "Taskware Manager"
        severity = "critical"
        
    strings:
        $s1 = "encrypt" ascii nocase
        $s2 = "decrypt" ascii nocase
        $s3 = "ransom" ascii nocase
        $s4 = "bitcoin" ascii nocase
        $s5 = "wallet" ascii nocase
        $s6 = "onion_address" ascii nocase
        $lib1 = "libcrypto" ascii
        $lib2 = "EVP_EncryptInit" ascii
        
    condition:
        uint32(0) == 0x464C457F and
        3 of ($s*) and 1 of ($lib*)
}

rule Linux_Ransomware_REvil
{
    meta:
        description = "Detects REvil / Sodinokibi Linux variants"
        author = "Taskware Manager"
        severity = "critical"
        
    strings:
        $s1 = "esxi" ascii nocase
        $s2 = "vmid" ascii nocase
        $s3 = "esxcli" ascii nocase
        $s4 = "vim-cmd" ascii nocase
        $s5 = "README-recover" ascii nocase
        
    condition:
        uint32(0) == 0x464C457F and
        4 of ($s*)
}
