"""
Taskware Manager - Heuristic Analysis (Linux Only)
Detection logic for suspicious process behavior on Linux.
"""

import math
import re
import os
import subprocess
import logging
from typing import Dict, List, Optional, Tuple

from taskware.config import ENTROPY_THRESHOLD, LEGITIMATE_PARENTS

logger = logging.getLogger("taskware.heuristics")


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return entropy


def check_file_entropy(filepath: str) -> Tuple[bool, float]:
    """
    Check if a file has suspiciously high entropy (packed / encrypted).
    Returns (is_suspicious, entropy_value).
    """
    try:
        with open(filepath, 'rb') as f:
            data = f.read(1024 * 1024)  # Read up to 1MB
        entropy = calculate_entropy(data)
        return entropy > ENTROPY_THRESHOLD, entropy
    except (PermissionError, OSError):
        return False, 0.0


def check_elf_section_entropy(filepath: str) -> List[Dict]:
    """
    Check entropy of individual ELF sections using readelf + reading raw.
    Returns list of suspicious sections.
    """
    suspicious = []
    try:
        result = subprocess.run(
            ['readelf', '-S', filepath],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return []

        # Parse section headers for offset and size
        with open(filepath, 'rb') as f:
            raw = f.read()

        for line in result.stdout.split('\n'):
            # Simple extraction of section name, offset, size
            parts = line.strip().split()
            if len(parts) >= 6 and parts[0].startswith('['):
                try:
                    name = parts[1]
                    offset = int(parts[4], 16)
                    size = int(parts[5], 16)
                    if size > 64:  # Ignore tiny sections
                        section_data = raw[offset:offset+size]
                        ent = calculate_entropy(section_data)
                        if ent > ENTROPY_THRESHOLD:
                            suspicious.append({
                                'name': name,
                                'entropy': ent,
                                'size': size,
                            })
                except (ValueError, IndexError):
                    continue
    except Exception:
        pass
    return suspicious


def detect_process_hollowing(
    pid: int,
    exe_path: str,
    memory_rss: int,
    num_threads: int,
) -> Tuple[bool, List[str]]:
    """
    Detect potential process hollowing on Linux.
    Checks for discrepancies between the on-disk binary and in-memory image.

    Indicators:
    - exe deleted from disk (shown as "(deleted)" in /proc)
    - maps showing unexpected rwx regions
    - threads spawned from non-standard locations
    """
    indicators = []

    # Check if executable was deleted (common in hollowing)
    try:
        exe_link = os.readlink(f"/proc/{pid}/exe")
        if "(deleted)" in exe_link:
            indicators.append("Binary deleted from disk after execution")
    except (OSError, PermissionError):
        pass

    # Check for RWX memory regions (unusual, suggests injected code)
    try:
        with open(f"/proc/{pid}/maps", 'r') as f:
            rwx_count = 0
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and 'rwx' in parts[1]:
                    rwx_count += 1
            if rwx_count > 0:
                indicators.append(
                    f"{rwx_count} RWX memory region(s) — potential code injection"
                )
    except (OSError, PermissionError):
        pass

    # Check for memfd_create-based anonymous execution
    try:
        exe_link = os.readlink(f"/proc/{pid}/exe")
        if "memfd:" in exe_link:
            indicators.append(
                "Executable runs from memfd (anonymous memory) — fileless malware"
            )
    except (OSError, PermissionError):
        pass

    return bool(indicators), indicators


def check_parent_child_anomaly(
    process_name: str,
    parent_name: str,
    parent_pid: int,
) -> Tuple[bool, str]:
    """
    Detect if the parent-child relationship is unusual on Linux.
    """
    # Suspicious: common system processes spawned by unexpected parents
    suspicious_children = {
        "bash": ["systemd", "sshd", "bash", "tmux: server", "screen",
                 "sudo", "su", "login", "cron", "at", "gnome-terminal", "konsole", "xterm", "alacritty", "kitty", "wezterm"],
        "sh": ["systemd", "sshd", "bash", "tmux: server", "screen",
               "sudo", "su", "cron", "at", "dockerd", "containerd"],
        "dash": ["systemd", "sshd", "bash", "tmux: server", "screen", "sudo", "su", "cron", "at"],
        "python3": ["bash", "sh", "systemd", "cron", "sshd", "sudo"],
        "python": ["bash", "sh", "systemd", "cron", "sshd", "sudo"],
        "curl": ["bash", "sh", "systemd", "cron", "apt", "yum", "dnf", "pacman", "apk"],
        "wget": ["bash", "sh", "systemd", "cron", "apt", "yum", "dnf", "pacman", "apk"],
        "nc": ["bash", "sh"],
        "ncat": ["bash", "sh"],
        "socat": ["bash", "sh"],
    }

    known_parents = suspicious_children.get(process_name.lower())
    if known_parents and parent_name.lower() not in [p.lower() for p in known_parents]:
        return True, (
            f"Unusual parent: '{parent_name}' spawned '{process_name}' "
            f"(expected one of: {', '.join(known_parents)})"
        )

    # Shell spawned by a non-interactive process / service
    shell_names = {"bash", "sh", "zsh", "fish", "dash", "csh", "tcsh", "ksh"}
    web_servers = {"apache2", "nginx", "httpd", "lighttpd",
                   "node", "uwsgi", "gunicorn", "tomcat", "java", "php-fpm", "ruby"}
    db_servers = {"mysqld", "postgres", "redis-server", "mongod", "oracle"}

    if process_name.lower() in shell_names:
        if parent_name.lower() in web_servers:
            return True, (
                f"Web server '{parent_name}' spawned shell '{process_name}' "
                f"— possible web shell or RCE"
            )
        if parent_name.lower() in db_servers:
            return True, (
                f"Database '{parent_name}' spawned shell '{process_name}' "
                f"— possible SQL injection / UDF exploitation"
            )

    return False, ""


def check_suspicious_cmdline(cmdline: str) -> Tuple[bool, List[str]]:
    """
    Check command line for suspicious patterns (Linux-specific).
    """
    if not cmdline:
        return False, []

    flags = []
    cmdline_lower = cmdline.lower()

    patterns = [

        # --- Advanced Obfuscation & Encoding ---
        (r"xxd\s+-r", "Hex decode via xxd"),
        (r"python\s+-c\s+.*base64\.b64decode", "Python base64 decode"),
        (r"perl\s+-MMIME::Base64", "Perl Base64 decode execution"),
        (r"echo\s+-e\s+\"[\\\\x0-9a-f]+\"", "Hex encoded command execution"),
        (r"rev\s*\|\s*(ba)?sh", "Execution of reverse strings"),
        (r"/bin/(ba)?sh\s+-c\s*'[A-Za-z0-9+/=]+'\s*\|\s*base64", "Wrapped Base64 execution"),

        # --- Reverse Shells & Bind Shells (Expanded) ---
        (r"bash\s+-i\s+>&?\s*/dev/tcp/", "Reverse shell (bash /dev/tcp)"),
        (r"nc\s+.*-e\s+/bin/(ba)?sh", "Reverse shell (netcat -e)"),
        (r"nc\s+-c\s+(ba)?sh", "Reverse shell (netcat -c)"),
        (r"nc\s+-lv(np|p)\s+", "Netcat bind shell listener"),
        (r"rm\s+/tmp/f;\s*mkfifo\s+/tmp/f;\s*cat\s+/tmp/f", "Reverse shell (netcat local pipe)"),
        (r"ncat\s+.*-e\s+/bin/(ba)?sh", "Reverse shell (ncat)"),
        (r"socat\s+.*exec:", "Reverse shell (socat)"),
        (r"socat\s+tcp-listen", "Socat bind shell"),
        (r"python.*socket.*connect.*pty", "Reverse shell (Python pty)"),
        (r"python.*-c.*import\s+pty.*pty\.spawn", "Reverse shell (Python spawn)"),
        (r"perl\s+-e\s+.*socket.*exec", "Reverse shell (Perl)"),
        (r"ruby\s+-rsocket\s+-e\s+.*TCPSocket", "Reverse shell (Ruby)"),
        (r"php\s+-r\s+.*fsockopen.*exec", "Reverse shell (PHP)"),
        (r"php\s+-S\s+0\.0\.0\.0:", "PHP built-in server (Potential backdoor)"),
        (r"awk\s+'BEGIN\s*{s\s*=\s*\"/inet/tcp/", "Reverse shell (AWK)"),
        (r"lua\s+-e\s+\"require\('socket'\)", "Reverse shell (Lua)"),
        (r"telnet\s+.*\s+\|\s*/bin/(ba)?sh\s+\|", "Reverse shell (Telnet pipe)"),

        # --- Base64 Encoded Payloads ---
        (r"base64\s+-d\s*\|", "Base64 decode piped to execution"),
        (r"echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64", "Base64-encoded payload"),
        (r"\|\s*base64\s+--decode\s*\|\s*(ba)?sh", "Base64 decode piped to shell"),

        # --- Privilege Escalation / Overprivileged Executions ---
        (r"chmod\s+[47]777", "World-writable permissions set"),
        (r"chmod\s+u\+s", "SUID bit set"),
        (r"chown\s+root:root", "Ownership changed to root"),
        (r"echo\s+.*ALL=\(ALL\)\s+NOPASSWD:ALL\s+>>\s+/etc/sudoers", "Sudoers modification (NOPASSWD)"),
        (r"usermod\s+-aG\s+(sudo|wheel)", "Added user to admin group"),
        (r"sudo\s+su\s+-", "Unattended root pivot via sudo su"),
        (r"pkexec\s+", "Polkit execution (potential PwnKit exploitation)"),
        (r"unshare\s+-r", "Unshare execution (User namespace root pivot)"),

        # --- Post-Exploitation Tooling ---
        (r"linpeas", "LinPEAS privilege escalation scanner"),
        (r"lse\.sh", "Linux Smart Enumeration script"),
        (r"pspy64", "pspy (Process snooping toolkit)"),
        (r"linux-exploit-suggester", "Linux Exploit Suggester"),
        (r"traitor\s+", "Traitor privesc tool execution"),

        # --- Tunneling & Proxies ---
        (r"chisel\s+(client|server)", "Chisel tunneling toolkit"),
        (r"ngrok\s+tcp", "Ngrok TCP tunnel (Payload exposure)"),
        (r"ssh\s+-R\s+[0-9]+:localhost:[0-9]+", "SSH Remote Port Forwarding (Reverse Tunneling)"),
        (r"ssh\s+-D\s+[0-9]+", "SSH Dynamic Port Forwarding (SOCKS proxy)"),
        (r"ligolo-ng", "Ligolo-NG tunneling tool"),
        (r"frpc\s+-c|frps\s+-c", "FRP Reverse Proxy"),

        # --- Persistence Mechanisms ---
        (r"/etc/cron\.", "Crontab persistence attempt"),
        (r"echo\s+.*>>\s*/var/spool/cron/", "User crontab modification"),
        (r"\.bashrc|\.profile|\.bash_profile", "Shell profile modification"),
        (r"/etc/systemd/system/.*\.service", "Systemd service creation"),
        (r"systemctl\s+(enable|start)\s+", "Systemd service manipulated"),
        (r"echo\s+.*>>\s*/etc/ld\.so\.preload", "LD_PRELOAD persistence setup"),
        (r"ssh-keygen\s+-t\s+rsa\s+-f\s+.*\.ssh/id_rsa", "SSH key generation (backdoor)"),
        (r"echo\s+ssh-rsa\s+.*>>\s+.*\.ssh/authorized_keys", "SSH authorized_keys modification"),
        (r"modprobe\s+", "Kernel module manipulation (Possible LKM rootkit load)"),
        (r"insmod\s+.*\.ko", "Kernel module insertion"),

        # --- Data Exfiltration & Fileless Execution ---
        (r"curl.*-d\s+@", "Data exfiltration via curl"),
        (r"curl\s+-s\s+http.*\|\s*(ba)?sh", "Curl piped to shell (fileless exec)"),
        (r"wget.*--post-file", "Data exfiltration via wget"),
        (r"wget\s+-qO-\s+http.*\|\s*(ba)?sh", "Wget piped to shell (fileless exec)"),
        (r"tftp\s+-c\s+(get|put)", "TFTP file transfer (older fallback)"),
        (r"scp\s+.*@.*:", "SCP file exfiltration"),

        # --- Suspicious Execution Locations ---
        (r"/dev/mqueue/", "Execution from message queue memory (/dev/mqueue)"),
        (r"/dev/shm/", "Execution from shared memory (/dev/shm)"),
        (r"/run/user/", "Execution from volatile /run/ directory"),
        (r"/tmp/.*\.sh", "Script execution directly from /tmp"),
        (r"/var/tmp/.*", "Execution from /var/tmp"),
        
        # --- Process Injection & IPC Abuse ---
        (r"mkfifo", "Named pipe creation (possible IPC abuse)"),
        (r"mknod\s+.*\s+p", "Named pipe creation via mknod"),
        (r"LD_PRELOAD=", "LD_PRELOAD hijacking"),
        (r"LD_LIBRARY_PATH=", "LD path manipulation"),
        (r"nohup\s+/tmp/.*&\s*", "Detached execution from /tmp"),
        (r"gdb\s+-batch", "GDB execution (Possible process injection/hollowing)"),

        # --- Crypto Mining ---
        (r"stratum\+tcp://", "Crypto miner (stratum protocol)"),
        (r"stratum\+ssl://", "Crypto miner (stratum protocol SSL)"),
        (r"xmrig|minerd|cpuminer|cgminer|ethminer", "Crypto miner binary executed"),
        (r"--donate-level=", "Crypto miner (XMRig donate flag)"),

        # --- Anti-Forensics / Defense Evasion ---
        (r"shred\s+-", "Secure file deletion (anti-forensics)"),
        (r"wipe\s+-", "Secure wipe tool execution"),
        (r"history\s+-c", "History clearing"),
        (r"unset\s+HISTFILE", "History file suppression"),
        (r"rm\s+-rf\s+/var/log", "Log deletion attempt"),
        (r"echo\s+>\s+/var/log/(syslog|auth\.log|secure)", "Log truncation attempt"),
        (r"ln\s+-sf\s+/dev/null\s+\~/\.bash_history", "History linked to /dev/null"),
        (r"set\s+\+o\s+history", "History recording disabled"),
        (r"touch\s+-am\s+-t", "Timestomping attack (touch timeline manipulation)"),
        
        # --- Internal Network Recon / Utilities ---
        (r"masscan\s+", "Masscan execution (Internal network scanning)"),
        (r"nmap\s+-sS\s+", "Nmap stealth SYN scan"),
        (r"nmap\s+-sV\s+", "Nmap service footprinting"),
        (r"zmap\s+-p\s+", "Zmap fast internet scanning"),
        (r"chattr\s+\+i\s+", "Immutable bit set (defense evasion)"),
        (r"ip\s+ neigh", "ARP cache enumeration"),
        (r"arp\s+-a", "ARP cache enumeration"),

    ]

    for pattern, description in patterns:
        if re.search(pattern, cmdline_lower):
            flags.append(description)

    return bool(flags), flags


def check_disk_binary_mismatch(pid: int) -> Tuple[bool, str]:
    """
    Compare the on-disk binary hash with the in-memory image.
    Detects if the running code differs from the executable on disk.
    """
    try:
        import hashlib

        # Get real exe path
        exe_path = os.readlink(f"/proc/{pid}/exe")
        if "(deleted)" in exe_path:
            return True, "Binary deleted from disk"

        # Hash the on-disk file
        with open(exe_path, 'rb') as f:
            disk_hash = hashlib.sha256(f.read(65536)).hexdigest()

        # Read first 64KB from /proc/pid/mem at the ELF entry point
        # (simplified check — real implementation would parse ELF headers)
        maps_path = f"/proc/{pid}/maps"
        with open(maps_path, 'r') as f:
            first_line = f.readline()
            if not first_line:
                return False, ""
            addr_range = first_line.split()[0]
            start = int(addr_range.split('-')[0], 16)

        with open(f"/proc/{pid}/mem", 'rb') as f:
            f.seek(start)
            mem_data = f.read(65536)
            mem_hash = hashlib.sha256(mem_data).hexdigest()

        if disk_hash != mem_hash:
            return True, "On-disk binary differs from in-memory image"

    except (OSError, PermissionError):
        pass
    except Exception:
        pass

    return False, ""
