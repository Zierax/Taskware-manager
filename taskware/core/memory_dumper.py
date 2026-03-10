"""
Taskware Manager - Memory Dumper (Linux Only)
Dump process memory using /proc filesystem.
Enhanced with verbose memory analysis from hack.py.
"""

import os
import string
import logging
from typing import Optional, List, Dict

import psutil

from taskware.config import DUMPS_DIR

logger = logging.getLogger("taskware.memory_dumper")


class MemoryDumper:
    """
    Linux memory dumper using /proc/pid/maps and /proc/pid/mem.
    """

    def __init__(self, dump_dir: str = DUMPS_DIR):
        self._dump_dir = dump_dir
        os.makedirs(self._dump_dir, exist_ok=True)

    def dump_process(self, pid: int) -> Optional[str]:
        """
        Create a verbose memory dump for a process.
        Extracts all readable memory regions and printable strings.

        Args:
            pid: Process ID to dump

        Returns:
            Path to the dump file, or None on failure
        """
        maps_path = f"/proc/{pid}/maps"
        mem_path = f"/proc/{pid}/mem"
        output_path = os.path.join(self._dump_dir, f"dump_{pid}.txt")
        printable_chars = set(bytes(string.printable, 'ascii'))

        total_regions = 0
        regions_with_strings = 0
        total_size_kb = 0

        try:
            # Verify process exists
            try:
                p = psutil.Process(pid)
                proc_name = p.name()
                proc_status = p.status()
                if proc_status == psutil.STATUS_ZOMBIE:
                    self._write_error(output_path, pid,
                                     "Process is zombie (already exited)")
                    return output_path
            except psutil.NoSuchProcess:
                self._write_error(output_path, pid, "Process not found")
                return output_path

            with open(maps_path, 'r') as maps_file, \
                 open(mem_path, 'rb') as mem_file, \
                 open(output_path, 'w', encoding='utf-8') as out:

                out.write(f"{'='*60}\n")
                out.write(f" TASKWARE MEMORY DUMP\n")
                out.write(f" PID: {pid}  |  Name: {proc_name}\n")
                out.write(f"{'='*60}\n\n")

                for line in maps_file:
                    total_regions += 1
                    parts = line.split(maxsplit=5)
                    addr_range = parts[0]
                    perms = parts[1]
                    pathname = parts[-1].strip() if len(parts) > 5 else "[anon]"

                    try:
                        start_hex, end_hex = addr_range.split('-')
                        start = int(start_hex, 16)
                        end = int(end_hex, 16)
                        size_kb = (end - start) / 1024
                        total_size_kb += size_kb
                    except ValueError:
                        size_kb = 0

                    out.write(f"── Region: {addr_range} [{perms}] "
                              f"{size_kb:.0f}KB  {pathname}\n")

                    if 'r' not in perms:
                        out.write("   (not readable)\n\n")
                        continue

                    try:
                        mem_file.seek(start)
                        chunk = mem_file.read(end - start)

                        found_strings = []
                        current = ""
                        for byte in chunk:
                            if byte in printable_chars:
                                current += chr(byte)
                            else:
                                if len(current) >= 4:
                                    found_strings.append(current)
                                current = ""
                        if len(current) >= 4:
                            found_strings.append(current)

                        if found_strings:
                            regions_with_strings += 1
                            out.write(f"   Strings ({len(found_strings)}):\n")
                            for s in found_strings[:150]:
                                out.write(f"     {s}\n")
                            if len(found_strings) > 150:
                                out.write(
                                    f"     ... and {len(found_strings)-150} more\n"
                                )
                        out.write("\n")

                    except (OSError, ValueError) as e:
                        out.write(f"   (read error: {e})\n\n")
                        continue

                out.write(f"\n{'='*60}\n")
                out.write(f" Summary\n")
                out.write(f"   Total Regions:          {total_regions}\n")
                out.write(f"   Regions with Strings:   {regions_with_strings}\n")
                out.write(f"   Total Memory Mapped:    {total_size_kb:.0f} KB\n")
                out.write(f"{'='*60}\n")

            logger.info(f"Memory dump saved: {output_path}")
            return output_path

        except FileNotFoundError:
            self._write_error(output_path, pid,
                             "Process not found in /proc (may have exited)")
            return output_path
        except PermissionError:
            self._write_error(output_path, pid,
                             "Permission denied — run as root (sudo)")
            return output_path
        except Exception as e:
            self._write_error(output_path, pid, str(e))
            return output_path

    def dump_raw_memory(self, pid: int) -> Optional[str]:
        """
        Create a raw binary memory dump (.dmp) file.
        Dumps all readable memory regions concatenated.
        """
        output_path = os.path.join(self._dump_dir, f"raw_{pid}.dmp")
        maps_path = f"/proc/{pid}/maps"
        mem_path = f"/proc/{pid}/mem"

        try:
            with open(maps_path, 'r') as maps_file, \
                 open(mem_path, 'rb') as mem_file, \
                 open(output_path, 'wb') as out:

                for line in maps_file:
                    parts = line.split()
                    if len(parts) < 2:
                        continue

                    addr_range = parts[0]
                    perms = parts[1]

                    if 'r' not in perms:
                        continue

                    try:
                        start_hex, end_hex = addr_range.split('-')
                        start = int(start_hex, 16)
                        end = int(end_hex, 16)

                        mem_file.seek(start)
                        data = mem_file.read(end - start)
                        out.write(data)
                    except (OSError, ValueError):
                        continue

            logger.info(f"Raw memory dump: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Raw dump failed for PID {pid}: {e}")
            return None

    def get_dump_list(self) -> List[Dict]:
        """List all existing memory dumps."""
        dumps = []
        try:
            for f in os.listdir(self._dump_dir):
                if f.startswith(('dump_', 'raw_')):
                    fpath = os.path.join(self._dump_dir, f)
                    stat = os.stat(fpath)
                    dumps.append({
                        'filename': f,
                        'path': fpath,
                        'size': stat.st_size,
                        'modified': stat.st_mtime,
                    })
        except Exception:
            pass
        dumps.sort(key=lambda x: x['modified'], reverse=True)
        return dumps

    @staticmethod
    def _write_error(path: str, pid: int, message: str):
        """Write an error report to the dump file."""
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(f"Memory Dump Error for PID: {pid}\n")
                f.write(f"{'='*50}\n\n")
                f.write(f"Error: {message}\n")
        except Exception:
            pass
