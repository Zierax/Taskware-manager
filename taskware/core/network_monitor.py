"""
Taskware Manager - Network Monitor (Linux Only)
Real-time network connection monitoring using psutil.
"""

import socket
import logging
import time
from typing import Dict, List, Optional
from dataclasses import dataclass

import psutil

logger = logging.getLogger("taskware.network_monitor")

@dataclass
class ConnectionInfo:
    """Represents a single active network connection."""
    pid: int
    process_name: str
    family: str
    conn_type: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    dns_resolved: str
    has_dns: bool



class NetworkMonitor:
    """
    Monitors active network connections and performs DNS analysis.
    """

    def __init__(self):
        self._dns_cache: Dict[str, str] = {}
        self._last_connections: List[ConnectionInfo] = []

    def get_all_connections(self) -> List[ConnectionInfo]:
        """
        Get all active network connections across the system.
        Returns a list of ConnectionInfo objects.
        """
        connections = []

        try:
            for conn in psutil.net_connections(kind='inet'):
                pid = conn.pid or 0
                process_name = ''
                if pid:
                    try:
                        proc = psutil.Process(pid)
                        process_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_name = 'N/A'

                laddr_ip = conn.laddr.ip if conn.laddr else ''
                laddr_port = conn.laddr.port if conn.laddr else 0
                raddr_ip = conn.raddr.ip if conn.raddr else ''
                raddr_port = conn.raddr.port if conn.raddr else 0
                
                dns_name = ''
                has_dns = False

                if raddr_ip:
                    dns_name = self._resolve_dns(raddr_ip)
                    has_dns = (dns_name != raddr_ip)

                entry = ConnectionInfo(
                    pid=pid,
                    process_name=process_name,
                    family=str(conn.family).split('.')[-1],
                    conn_type=str(conn.type).split('.')[-1],
                    local_addr=laddr_ip,
                    local_port=laddr_port,
                    remote_addr=raddr_ip,
                    remote_port=raddr_port,
                    status=conn.status,
                    dns_resolved=dns_name,
                    has_dns=has_dns
                )

                connections.append(entry)

        except (psutil.AccessDenied, PermissionError) as e:
            logger.warning(f"Network access denied: {e}")
        except Exception as e:
            logger.error(f"Error getting connections: {e}")

        self._last_connections = connections
        return connections

    def get_connections_for_pid(self, pid: int) -> List[ConnectionInfo]:
        """Get connections for a specific process."""
        try:
            proc = psutil.Process(pid)
            process_name = proc.name()
            conns = []
            for conn in proc.net_connections(kind='inet'):
                laddr_ip = conn.laddr.ip if conn.laddr else ''
                laddr_port = conn.laddr.port if conn.laddr else 0
                raddr_ip = conn.raddr.ip if conn.raddr else ''
                raddr_port = conn.raddr.port if conn.raddr else 0
                
                dns_name = ''
                has_dns = False

                if raddr_ip:
                    dns_name = self._resolve_dns(raddr_ip)
                    has_dns = (dns_name != raddr_ip)

                entry = ConnectionInfo(
                    pid=pid,
                    process_name=process_name,
                    family=str(conn.family).split('.')[-1],
                    conn_type=str(conn.type).split('.')[-1],
                    local_addr=laddr_ip,
                    local_port=laddr_port,
                    remote_addr=raddr_ip,
                    remote_port=raddr_port,
                    status=conn.status,
                    dns_resolved=dns_name,
                    has_dns=has_dns
                )
                conns.append(entry)
            return conns
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []

    def get_established_count(self) -> int:
        """Count established connections."""
        return sum(
            1 for c in self._last_connections
            if c.status == 'ESTABLISHED'
        )

    def get_no_dns_count(self) -> int:
        """Count connections without DNS resolution."""
        return sum(
            1 for c in self._last_connections
            if not c.has_dns and c.remote_addr
        )

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if an IP address is private/local."""
        if not ip:
            return False
        return ip.startswith(('127.', '10.', '192.168.', '0.', '::1', 'fe80:')) \
               or (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31)

    def _resolve_dns(self, ip: str) -> str:
        """Resolve IP to hostname (cached)."""
        if ip in self._dns_cache:
            return self._dns_cache[ip]

        # Skip private/local IPs
        if ip.startswith(('127.', '0.', '::1', 'fe80:')):
            self._dns_cache[ip] = ip
            return ip

        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self._dns_cache[ip] = hostname
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            self._dns_cache[ip] = ip
            return ip
