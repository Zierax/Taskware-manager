/*
    Taskware Manager - Linux Botnet Rules
    Detects common IoT/Linux botnets like Mirai, Gafgyt, Tsunami, XorDDOS.
*/

rule Linux_Mirai_Botnet
{
    meta:
        description = "Detects Mirai IoT Botnet variants"
        author = "Taskware Manager"
        severity = "critical"
        
    strings:
        $s1 = "/bin/busybox" ascii
        $s2 = "POST /cdn-cgi/" ascii
        $s3 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64)" ascii
        $s4 = "LCOGQ" ascii
        $s5 = "zmap" ascii nocase
        $s6 = "mirai" ascii nocase
        $s7 = "applinzi" ascii
        $s8 = "watchdog" ascii
        
    condition:
        uint32(0) == 0x464C457F and 
        3 of ($s*)
}

rule Linux_Gafgyt_Bashlite
{
    meta:
        description = "Detects Gafgyt / Bashlite DDoS bot"
        author = "Taskware Manager"
        severity = "critical"
        
    strings:
        $s1 = "HTTP Flooding" ascii nocase
        $s2 = "PING" ascii fullword
        $s3 = "PONG" ascii fullword
        $s4 = "GETLOCALIP" ascii
        $s5 = "/bin/busybox" ascii
        $s6 = "LIZARD" ascii
        $s7 = "bashlite" ascii nocase
        
    condition:
        uint32(0) == 0x464C457F and 
        4 of ($s*)
}

rule Linux_Tsunami_Kaiten
{
    meta:
        description = "Detects Tsunami / Kaiten IRC bot"
        author = "Taskware Manager"
        severity = "high"
        
    strings:
        $irc1 = "PRIVMSG %s :%s" ascii
        $irc2 = "NOTICE %s :%s" ascii
        $irc3 = "JOIN %s" ascii
        $irc4 = "USER %s %s %s :%s" ascii
        $cmd1 = "Kaiten" ascii
        $cmd2 = "tsunami" ascii nocase
        $cmd3 = "PANIC" ascii fullword
        
    condition:
        uint32(0) == 0x464C457F and
        3 of ($irc*) and 1 of ($cmd*)
}

rule Linux_XorDDOS
{
    meta:
        description = "Detects XorDDOS malware"
        author = "Taskware Manager"
        severity = "critical"
        
    strings:
        $s1 = "BB2FA36AAA9541F0" ascii
        $s2 = "/lib/libudev.so" ascii
        $s3 = "/etc/cron.hourly/gcc.sh" ascii
        $s4 = "XOR_encode" ascii
        $s5 = "xorddos" ascii nocase
        
    condition:
        uint32(0) == 0x464C457F and
        2 of ($s*)
}

rule Linux_Mozi_Botnet
{
    meta:
        description = "Detects Mozi P2P Botnet"
        author = "Taskware Manager"
        severity = "critical"
        
    strings:
        $s1 = "[ssdp]" ascii
        $s2 = "[dht]" ascii
        $s3 = "Mozi" ascii
        $s4 = "/usr/bin/wget" ascii
        $s5 = "cpu:%s;os:%s;arch:%s" ascii
        
    condition:
        uint32(0) == 0x464C457F and
        3 of ($s*)
}
