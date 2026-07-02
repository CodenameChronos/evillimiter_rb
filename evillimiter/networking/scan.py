import sys
import socket
import subprocess
from tqdm import tqdm
from netaddr import IPAddress
from scapy.all import sr1, ARP
from concurrent.futures import ThreadPoolExecutor
from mac_vendor_lookup import MacLookup, VendorNotFoundError  # ← nuevo
from .host import Host
from evillimiter.console.io import IO

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import sr1, ARP, conf
conf.verb = 0  # Silencia todos los warnings de scapy

class HostScanner(object):
    def __init__(self, interface, iprange):
        self.interface = interface
        self.iprange = iprange
        self.max_workers = 75
        self.retries = 0
        self.timeout = 2.5
        # Precarga la base de datos de fabricantes
        self.mac_lookup = MacLookup()

    def _resolve_dns(self, ip):
        try:
            info = socket.gethostbyaddr(ip)
            if info and info[0]:
                return info[0].split('.')[0]
        except (socket.herror, socket.gaierror):
            pass
        return None

    def _resolve_netbios(self, ip):
        try:
            result = subprocess.run(
                ['nmblookup', '-A', ip],
                capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if '<00>' in line and 'GROUP' not in line:
                    return line.split('<00>')[0].strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    def _resolve_mdns(self, ip):
        try:
            result = subprocess.run(
                ['avahi-resolve', '--address', ip],
                capture_output=True, text=True, timeout=3
            )
            if result.stdout.strip():
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    return parts[1].replace('.local', '')
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    def _resolve_vendor(self, mac):
        """Busca el fabricante del dispositivo por MAC"""
        try:
            return self.mac_lookup.lookup(mac)
        except VendorNotFoundError:
            return None
        except Exception:
            return None

    def _resolve_name(self, ip, mac):
        """Combina hostname y fabricante para mejor identificación"""
        hostname = (
            self._resolve_dns(ip) or
            self._resolve_netbios(ip) or
            self._resolve_mdns(ip)
        )
        vendor = self._resolve_vendor(mac)

        if hostname and vendor:
            return f'{hostname} ({vendor})'
        elif hostname:
            return hostname
        elif vendor:
            return vendor
        return ''

    def scan(self, iprange=None):
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            hosts = []
            iprange = [str(x) for x in (self.iprange if iprange is None else iprange)]
            iterator = tqdm(
                iterable=executor.map(self._sweep, iprange),
                total=len(iprange),
                ncols=45,
                bar_format='{percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt}'
            )
            try:
                for host in iterator:
                    if host is not None:
                        host.name = self._resolve_name(host.ip, host.mac)
                        hosts.append(host)
            except KeyboardInterrupt:
                iterator.close()
                IO.ok('aborted. waiting for shutdown...')
            return hosts

    def scan_for_reconnects(self, hosts, iprange=None):
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            scanned_hosts = []
            iprange = [str(x) for x in (self.iprange if iprange is None else iprange)]
            for host in executor.map(self._sweep, iprange):
                if host is not None:
                    scanned_hosts.append(host)
            reconnected_hosts = {}
            for host in hosts:
                for s_host in scanned_hosts:
                    if host.mac == s_host.mac and host.ip != s_host.ip:
                        s_host.name = host.name
                        reconnected_hosts[host] = s_host
            return reconnected_hosts

    def _sweep(self, ip):
        packet = ARP(op=1, pdst=ip)
        answer = sr1(packet, retry=self.retries, timeout=self.timeout, verbose=0, iface=self.interface)
        if answer is not None:
            return Host(ip, answer.hwsrc, '')
