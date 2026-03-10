"""
Taskware Manager - Process Monitor (Linux Only)
Real-time process telemetry collection using psutil.
Includes strace-based syscall tracing, binary analysis,
and ELF section analysis from the hack.py analysis toolkit.
"""

import os
import re
import time
import string
import hashlib
import logging
import subprocess
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple

import psutil

from taskware.config import SUSPICIOUS_PATHS

logger = logging.getLogger("taskware.process_monitor")


@dataclass
class ProcessInfo:
    """Comprehensive snapshot of a single process."""
    pid: int
    name: str = ""
    exe_path: str = ""
    cmdline: str = ""
    parent_pid: Optional[int] = None
    parent_name: str = ""
    username: str = ""
    status: str = ""
    create_time: float = 0.0
    cpu_percent: float = 0.0
    memory_rss: int = 0          # bytes
    memory_vms: int = 0          # bytes
    memory_percent: float = 0.0
    num_threads: int = 0
    num_connections: int = 0
    num_open_files: int = 0
    sha256: str = ""
    is_from_temp: bool = False
    children_pids: List[int] = field(default_factory=list)
    suspicion_score: int = 0
    flags: List[str] = field(default_factory=list)
    # ML prediction fields
    ml_prediction: str = ""
    ml_confidence: float = 0.0

    @property
    def memory_rss_mb(self) -> float:
        return self.memory_rss / (1024 * 1024)

    @property
    def memory_vms_mb(self) -> float:
        return self.memory_vms / (1024 * 1024)


class ProcessMonitor:
    """
    Collects real-time process telemetry on Linux.
    Designed to run in a QThread and emit process snapshots.
    """

    def __init__(self):
        self._hash_cache: Dict[str, str] = {}   # path -> sha256
        self._prev_snapshot: Dict[int, ProcessInfo] = {}

    def get_all_processes(self) -> Dict[int, ProcessInfo]:
        """Collect telemetry for all running processes."""
        snapshot: Dict[int, ProcessInfo] = {}

        for proc in psutil.process_iter(attrs=[
            'pid', 'name', 'exe', 'cmdline', 'ppid', 'username',
            'status', 'create_time', 'cpu_percent', 'memory_info',
            'memory_percent', 'num_threads'
        ]):
            try:
                info = proc.info
                pi = ProcessInfo(pid=info['pid'])
                pi.name = info.get('name', '') or ''
                pi.exe_path = info.get('exe', '') or ''
                pi.cmdline = ' '.join(info.get('cmdline') or [])
                pi.parent_pid = info.get('ppid')
                pi.username = info.get('username', '') or ''
                pi.status = info.get('status', '') or ''
                pi.create_time = info.get('create_time', 0.0) or 0.0
                pi.cpu_percent = info.get('cpu_percent', 0.0) or 0.0
                pi.num_threads = info.get('num_threads', 0) or 0

                mem = info.get('memory_info')
                if mem:
                    pi.memory_rss = mem.rss
                    pi.memory_vms = mem.vms
                pi.memory_percent = info.get('memory_percent', 0.0) or 0.0

                # Parent name
                if pi.parent_pid:
                    try:
                        parent = psutil.Process(pi.parent_pid)
                        pi.parent_name = parent.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pi.parent_name = "N/A"

                # Check if running from suspicious path
                pi.is_from_temp = self._is_suspicious_path(pi.exe_path)

                # Optimize: Get socket count directly from /proc/<pid>/fd length
                try:
                    fd_dir = f"/proc/{pi.pid}/fd"
                    if os.path.exists(fd_dir):
                        pi.num_open_files = len(os.listdir(fd_dir))
                    else:
                        pi.num_open_files = 0
                except (PermissionError, OSError):
                    pi.num_open_files = 0

                # Optimize: We already have global network connections from NetworkMonitor
                # Doing it per process here is duplicative and takes O(N) time.
                pi.num_connections = 0  # To be populated later by RuleEngine if needed

                # Children - Optimize: building tree later is faster than querying each process
                pi.children_pids = []

                # SHA256 hash (cached) - optimize by only hashing suspicious paths by default
                if pi.exe_path and pi.is_from_temp and os.path.isfile(pi.exe_path):
                    pi.sha256 = self._get_file_hash(pi.exe_path)

                snapshot[pi.pid] = pi

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug(f"Error collecting process {proc.pid}: {e}")
                continue

        self._prev_snapshot = snapshot
        return snapshot

    def kill_process(self, pid: int) -> bool:
        """Terminate a process by PID."""
        try:
            proc = psutil.Process(pid)
            proc.kill()
            logger.info(f"Killed process {pid} ({proc.name()})")
            return True
        except Exception as e:
            logger.error(f"Failed to kill PID {pid}: {e}")
            return False

    def suspend_process(self, pid: int) -> bool:
        """Suspend a process by PID (SIGSTOP)."""
        try:
            proc = psutil.Process(pid)
            proc.suspend()
            logger.info(f"Suspended process {pid} ({proc.name()})")
            return True
        except Exception as e:
            logger.error(f"Failed to suspend PID {pid}: {e}")
            return False

    def resume_process(self, pid: int) -> bool:
        """Resume a suspended process by PID (SIGCONT)."""
        try:
            proc = psutil.Process(pid)
            proc.resume()
            logger.info(f"Resumed process {pid} ({proc.name()})")
            return True
        except Exception as e:
            logger.error(f"Failed to resume PID {pid}: {e}")
            return False

    def _is_suspicious_path(self, exe_path: str) -> bool:
        """Check if exe runs from a suspicious location."""
        if not exe_path:
            return False
        return any(sp in exe_path for sp in SUSPICIOUS_PATHS)

    def _get_file_hash(self, filepath: str) -> str:
        """Get SHA256 hash of a file (with caching)."""
        if filepath in self._hash_cache:
            return self._hash_cache[filepath]
        try:
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)
            h = sha256.hexdigest()
            self._hash_cache[filepath] = h
            return h
        except (PermissionError, OSError):
            return ""

    def get_process_tree(self) -> Dict[int, List[int]]:
        """Build parent->children process tree."""
        tree: Dict[int, List[int]] = {}
        for pid, pi in self._prev_snapshot.items():
            parent = pi.parent_pid or 0
            if parent not in tree:
                tree[parent] = []
            tree[parent].append(pid)
        return tree

    # ─── Functions ported from hack.py ────────────────────────────────────

    @staticmethod
    def get_file_info(file_path: str) -> Dict:
        """Get basic file information including size, type, and mode."""
        info = {}
        try:
            stat = os.stat(file_path)
            info['size'] = stat.st_size
            info['size_human'] = ProcessMonitor.format_file_size(stat.st_size)

            try:
                import magic
                file_type = magic.from_file(file_path)
                info['type'] = file_type
            except Exception:
                # fallback: use `file` command
                try:
                    result = subprocess.run(
                        ['file', '-b', file_path],
                        capture_output=True, text=True, timeout=5
                    )
                    info['type'] = result.stdout.strip()
                except Exception:
                    info['type'] = "Unknown"

            mode = stat.st_mode
            info['permissions'] = oct(mode)[-3:]
            info['is_executable'] = bool(mode & 0o111)

            if mode & 0o111:
                info['mode'] = "Executable"
            elif file_path.endswith('.so') or 'shared object' in info.get('type', '').lower():
                info['mode'] = "Shared Object"
            elif file_path.endswith('.o') or 'relocatable' in info.get('type', '').lower():
                info['mode'] = "Relocatable"
            else:
                info['mode'] = "Regular File"
        except Exception as e:
            info['error'] = str(e)
        return info

    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """Format file size in human readable format."""
        if size_bytes == 0:
            return "0B"
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        sz = float(size_bytes)
        while sz >= 1024 and i < len(size_names) - 1:
            sz /= 1024.0
            i += 1
        return f"{sz:.1f}{size_names[i]}"

    @staticmethod
    def calculate_hashes(file_path: str) -> Dict[str, str]:
        """Calculate MD5, SHA1, and SHA256 hashes."""
        hashes = {}
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            hashes['error'] = str(e)
        return hashes

    @staticmethod
    def get_compiler_packer_info(file_path: str) -> Dict[str, str]:
        """Detect compiler and packer information using strings."""
        info = {}
        try:
            result = subprocess.run(
                ['strings', file_path], capture_output=True,
                text=True, timeout=10
            )
            strings_output = result.stdout.lower()

            # Compiler detection
            if 'gcc' in strings_output or 'gnu' in strings_output:
                info['compiler'] = "GCC"
            elif 'clang' in strings_output:
                info['compiler'] = "Clang"
            elif 'rustc' in strings_output:
                info['compiler'] = "Rust (rustc)"
            elif 'go' in strings_output and 'runtime' in strings_output:
                info['compiler'] = "Go"
            else:
                info['compiler'] = "Unknown"

            packers = {
                'upx': 'UPX', 'aspack': 'ASPack', 'themida': 'Themida',
                'vmprotect': 'VMProtect', 'enigma': 'Enigma Protector',
                'obsidium': 'Obsidium', 'pecompact': 'PECompact',
            }
            for keyword, packer_name in packers.items():
                if keyword in strings_output:
                    info['packer'] = packer_name
                    break
            else:
                info['packer'] = "None detected"
        except Exception as e:
            info['error'] = str(e)
            info['compiler'] = "Unknown"
            info['packer'] = "Unknown"
        return info

    @staticmethod
    def extract_symbols(file_path: str) -> Dict[str, List[str]]:
        """Extract symbols from ELF binary file using nm/objdump."""
        symbols = {'functions': [], 'variables': [], 'error': None}
        try:
            result = subprocess.run(
                ['nm', '-D', file_path], capture_output=True,
                text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            sym_type = parts[1]
                            sym_name = parts[2]
                            if sym_type in ['T', 't']:
                                symbols['functions'].append(sym_name)
                            elif sym_type in ['D', 'd', 'B', 'b']:
                                symbols['variables'].append(sym_name)

            if not symbols['functions'] and not symbols['variables']:
                result = subprocess.run(
                    ['objdump', '-T', file_path], capture_output=True,
                    text=True, timeout=10
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'DF' in line or 'df' in line:
                            parts = line.split()
                            if len(parts) >= 6:
                                symbols['functions'].append(parts[-1])
                        elif 'DO' in line or 'do' in line:
                            parts = line.split()
                            if len(parts) >= 6:
                                symbols['variables'].append(parts[-1])
        except Exception as e:
            symbols['error'] = str(e)
        return symbols

    @staticmethod
    def analyze_elf_sections(file_path: str) -> Dict:
        """Analyze ELF sections using readelf."""
        sections_data = {'sections': [], 'error': None}
        try:
            result = subprocess.run(
                ['readelf', '-S', file_path], capture_output=True,
                text=True, timeout=10
            )
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if '[' in line and ']' in line and 'Section' not in line:
                        parts = line.split()
                        if len(parts) >= 6:
                            section_info = {
                                'name': parts[1].strip('[]'),
                                'type': parts[2],
                                'address': parts[3],
                                'offset': parts[4],
                                'size': parts[5],
                                'size_human': ProcessMonitor.format_file_size(
                                    int(parts[5], 16)
                                ) if parts[5] != '00000000' else '0B'
                            }
                            sections_data['sections'].append(section_info)

            if not sections_data['sections']:
                result = subprocess.run(
                    ['objdump', '-h', file_path], capture_output=True,
                    text=True, timeout=10
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        parts = line.split()
                        if len(parts) >= 7 and parts[0].isdigit():
                            sections_data['sections'].append({
                                'name': parts[1],
                                'size': parts[2],
                                'size_human': ProcessMonitor.format_file_size(
                                    int(parts[2], 16)
                                ),
                                'vma': parts[3],
                                'lma': parts[4],
                            })
        except Exception as e:
            sections_data['error'] = str(e)
        return sections_data

    @staticmethod
    def analyze_binary_strings(file_path: str) -> List[str]:
        """Extract interesting strings from binary file."""
        try:
            result = subprocess.run(
                ['strings', file_path], capture_output=True,
                text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout:
                strings_list = result.stdout.strip().split('\n')
                return [s for s in strings_list if len(s) >= 4][:500]
        except Exception:
            pass
        return []

    @staticmethod
    def trace_syscalls(pid: int, duration: int = 5) -> List[str]:
        """Trace syscalls of a running process using strace (requires root)."""
        try:
            result = subprocess.run(
                ['strace', '-f', '-p', str(pid), '-e', 'trace=all',
                 '-c', '-S', 'calls'],
                capture_output=True, text=True, timeout=duration + 2
            )
            syscalls = []
            for line in (result.stderr or '').split('\n'):
                parts = line.strip().split()
                if parts and len(parts) >= 5:
                    # strace -c output format: % time  seconds  usecs/call  calls  errors  syscall
                    try:
                        syscall_name = parts[-1]
                        if syscall_name.isalpha() or '_' in syscall_name:
                            syscalls.append(syscall_name)
                    except Exception:
                        continue
            return syscalls
        except subprocess.TimeoutExpired:
            return []
        except FileNotFoundError:
            logger.warning("strace not found — install with: sudo apt install strace")
            return []
        except Exception:
            return []

    @staticmethod
    def get_process_syscall_sequence(binary_path: str, timeout: int = 60) -> str:
        """
        Run a binary with strace and return its syscall sequence.
        Used for ML model prediction input.
        Ported from hack.py trace_syscalls_all().
        """
        try:
            cmd = ["strace", "-f", "-e", "trace=all", binary_path]
            result = subprocess.run(
                cmd, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL,
                text=True, timeout=timeout
            )
            syscall_pattern = re.compile(r"^([a-zA-Z0-9_]+)\(", re.MULTILINE)
            syscalls = syscall_pattern.findall(result.stderr or "")
            return " ".join(syscalls)
        except Exception:
            return ""

    @staticmethod
    def dump_process_memory_verbose(pid: int, output_dir: str) -> Optional[str]:
        """
        Verbose memory dump for a process using /proc/pid/maps + /proc/pid/mem.
        Extracted and improved from hack.py dump_verbose_memory_info().
        """
        maps_path = f"/proc/{pid}/maps"
        mem_path = f"/proc/{pid}/mem"
        output_filename = os.path.join(output_dir, f"memory_dump_{pid}.txt")
        printable_chars = set(bytes(string.printable, 'ascii'))

        total_regions = 0
        regions_with_strings = 0

        try:
            # Check process status
            try:
                p = psutil.Process(pid)
                if p.status() == psutil.STATUS_ZOMBIE:
                    with open(output_filename, 'w', encoding='utf-8') as out:
                        out.write(f"Memory Dump for PID: {pid}\n{'='*50}\n\n")
                        out.write("Process is zombie (already exited).\n")
                    return output_filename
            except psutil.NoSuchProcess:
                with open(output_filename, 'w', encoding='utf-8') as out:
                    out.write(f"Memory Dump for PID: {pid}\n{'='*50}\n\n")
                    out.write("Process not found.\n")
                return output_filename

            with open(maps_path, 'r') as maps_file, \
                 open(mem_path, 'rb') as mem_file, \
                 open(output_filename, 'w', encoding='utf-8') as out_file:

                out_file.write(f"Memory Dump for PID: {pid}\n{'='*50}\n\n")

                for line in maps_file:
                    total_regions += 1
                    out_file.write(f"Region: {line.strip()}\n")

                    parts = line.split(maxsplit=5)
                    addr_range = parts[0]
                    perms = parts[1]

                    if 'r' not in perms:
                        out_file.write("Region not readable.\n\n")
                        continue

                    try:
                        start_hex, end_hex = addr_range.split('-')
                        start = int(start_hex, 16)
                        end = int(end_hex, 16)

                        mem_file.seek(start)
                        chunk = mem_file.read(end - start)

                        found_strings = []
                        current_string = ""
                        for byte in chunk:
                            if byte in printable_chars:
                                current_string += chr(byte)
                            else:
                                if len(current_string) >= 4:
                                    found_strings.append(current_string)
                                current_string = ""
                        if len(current_string) >= 4:
                            found_strings.append(current_string)

                        if found_strings:
                            regions_with_strings += 1
                            out_file.write("Found printable strings:\n")
                            for s in found_strings[:200]:  # cap at 200
                                out_file.write(f"  - {s}\n")
                        out_file.write("\n" + "-"*20 + "\n\n")

                    except (OSError, ValueError) as e:
                        out_file.write(f"Could not read region: {e}\n\n")
                        continue

                out_file.write(f"\nTotal Regions: {total_regions}\n")
                out_file.write(f"Regions with Strings: {regions_with_strings}\n")

            logger.info(f"Memory dump saved: {output_filename}")
            return output_filename

        except FileNotFoundError:
            logger.error(f"Process {pid} not found in /proc")
        except PermissionError:
            logger.error(f"Permission denied for PID {pid} — run as root")
        except Exception as e:
            logger.error(f"Memory dump failed for PID {pid}: {e}")

        return None

    @staticmethod
    def parse_strace_log(log_path: str) -> List[str]:
        """Parse strace log for child process activity.
        Ported from hack.py parse_strace_log()."""
        report = []
        try:
            with open(log_path, "r") as f:
                for line in f:
                    line = line.strip()
                    m = re.match(r"(\d+)\s+(\w+)\((.*)\)\s+=\s+(.+)", line)
                    if not m:
                        continue
                    pid, syscall, args, result = m.groups()

                    if syscall == "execve":
                        parts = args.split(",")
                        prog = parts[0].strip('"')
                        report.append(f"PID {pid} executed {prog}")
                    elif syscall in ("clone", "fork"):
                        child_match = re.search(r"=\s+(\d+)", line)
                        if child_match:
                            child_pid = child_match.group(1)
                            report.append(
                                f"PID {pid} created child process "
                                f"(PID {child_pid}) via {syscall}()"
                            )
                    elif syscall == "write":
                        msg_match = re.search(r"\"(.*)\"", args)
                        if msg_match:
                            report.append(
                                f"PID {pid} wrote: \"{msg_match.group(1)[:80]}\""
                            )
        except Exception:
            pass
        return report
