"""NetSentry | PortShield - detection.py
Administrator check, Scapy / Npcap environment checks, network interface discovery,
TCP SYN packet filtering, AsyncSniffer lifecycle and the rolling-window PortScanDetector.

Depends only on the configuration constants in database.py.
"""
import ctypes
import os
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple

from database import (
    CAPTURE_FILTER,
    PORT_THRESHOLD,
    TCP_ACK_FLAG,
    TCP_SYN_FLAG,
    WINDOW_SECONDS,
)

def is_windows_admin() -> bool:
    """Check whether the current process holds Windows Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

try:
    from scapy.all import AsyncSniffer, IP, TCP, conf, get_if_addr, get_if_list
    SCAPY_AVAILABLE = True
    SCAPY_IMPORT_ERROR = ''
except Exception as _scapy_exc:
    AsyncSniffer = None
    IP = None
    TCP = None
    conf = None
    get_if_addr = None
    get_if_list = None
    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = str(_scapy_exc)

if os.name == 'nt':
    try:
        import winreg
    except Exception:
        winreg = None
else:
    winreg = None

_GUID_PATTERN = re.compile('\\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\\}')

@dataclass(frozen=True)
class NetworkInterfaceInfo:
    """Represents a capture interface with both its UI display label and raw Npcap device ID."""
    device_id: str
    friendly_name: str
    description: str
    ip_address: str
    display_label: str
    is_available: bool = True

def _extract_guid(device_id: str) -> Optional[str]:
    """Extract the uppercase Windows adapter {GUID} from an Npcap device path if present."""
    match = _GUID_PATTERN.search(device_id or '')
    return match.group(0).upper() if match else None

def _lookup_windows_registry_adapter(guid: str) -> Tuple[str, str]:
    """
    Query Windows Registry for the official Connection Name (e.g., 'Wi-Fi', 'Ethernet')
    and Hardware Description (e.g., 'Realtek PCIe GbE Family Controller') for a given {GUID}.
    Returns (friendly_name, description), either of which may be empty if not found.
    """
    if winreg is None or not guid:
        return ('', '')
    friendly_name = ''
    description = ''
    conn_subkey = f'SYSTEM\\CurrentControlSet\\Control\\Network\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\{guid}\\Connection'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, conn_subkey) as key:
            val, _ = winreg.QueryValueEx(key, 'Name')
            if isinstance(val, str) and val.strip():
                friendly_name = val.strip()
    except OSError:
        pass
    cards_subkey = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, cards_subkey) as cards_key:
            idx = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(cards_key, idx)
                    idx += 1
                except OSError:
                    break
                try:
                    with winreg.OpenKey(cards_key, sub_name) as card_key:
                        svc_name, _ = winreg.QueryValueEx(card_key, 'ServiceName')
                        if isinstance(svc_name, str) and svc_name.strip().upper() == guid:
                            desc_val, _ = winreg.QueryValueEx(card_key, 'Description')
                            if isinstance(desc_val, str) and desc_val.strip():
                                description = desc_val.strip()
                            break
                except OSError:
                    continue
    except OSError:
        pass
    return (friendly_name, description)

def _get_scapy_iface_metadata() -> Dict[str, Dict[str, str]]:
    """
    Inspect Scapy's `conf.ifaces` registry (when available) to map raw Npcap device paths
    to Windows friendly names, hardware descriptions, and IPv4 addresses.
    """
    metadata: Dict[str, Dict[str, str]] = {}
    if conf is None or not hasattr(conf, 'ifaces'):
        return metadata
    try:
        iface_values = list(conf.ifaces.values())
    except Exception:
        return metadata
    for iface_obj in iface_values:
        try:
            dev_name = str(getattr(iface_obj, 'network_name', '') or getattr(iface_obj, 'pcap_name', '') or '').strip()
            if not dev_name:
                continue
            friendly = str(getattr(iface_obj, 'name', '') or '').strip()
            desc = str(getattr(iface_obj, 'description', '') or '').strip()
            ip_val = str(getattr(iface_obj, 'ip', '') or '').strip()
            if friendly.startswith('\\Device\\NPF_'):
                friendly = ''
            metadata[dev_name] = {'friendly_name': friendly, 'description': desc, 'ip_address': ip_val if ip_val and ip_val != '0.0.0.0' else ''}
        except Exception:
            continue
    return metadata

def _safe_get_if_addr(device_id: str) -> str:
    """Safely query Scapy's get_if_addr() for an interface without raising on disconnected links."""
    if get_if_addr is None:
        return ''
    try:
        ip_addr = str(get_if_addr(device_id) or '').strip()
        if ip_addr and ip_addr != '0.0.0.0' and (not ip_addr.startswith('127.0.0.')):
            return ip_addr
        if ip_addr.startswith('127.0.0.'):
            return ip_addr
    except Exception:
        pass
    return ''

def check_capture_environment() -> Tuple[bool, str]:
    """Verify whether Scapy and Npcap capture support are available on this host."""
    if not SCAPY_AVAILABLE:
        return (False, f"Scapy packet capture library is unavailable: {SCAPY_IMPORT_ERROR or 'not installed'}.")
    if os.name == 'nt':
        npcap_dir = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'Npcap')
        winpcap_dll = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'wpcap.dll')
        if not (os.path.isdir(npcap_dir) or os.path.exists(winpcap_dll)):
            return (False, 'Npcap driver was not detected in System32. Install Npcap with WinPcap API-compatible mode enabled.')
    return (True, 'Packet capture environment ready.')

def list_network_interfaces(if_list_provider: Optional[Callable[[], List[str]]]=None) -> List[str]:
    """Return raw available network capture interface identifiers safely."""
    provider = if_list_provider or get_if_list
    if provider is None:
        return []
    try:
        interfaces = provider() or []
        return [str(iface) for iface in interfaces if str(iface).strip()]
    except Exception:
        return []

def list_detailed_network_interfaces(if_list_provider: Optional[Callable[[], List[str]]]=None) -> List[NetworkInterfaceInfo]:
    """
    Discover available Npcap interfaces via Scapy's get_if_list() / get_if_addr() / conf.ifaces
    and resolve each to its authentic Windows network adapter friendly name and description.
    Preserves the exact original Npcap device_id for packet capture.
    """
    raw_devices = list_network_interfaces(if_list_provider=if_list_provider)
    if not raw_devices:
        return []
    scapy_meta = _get_scapy_iface_metadata()
    resolved_items: List[NetworkInterfaceInfo] = []
    for device_id in raw_devices:
        meta = scapy_meta.get(device_id, {})
        friendly = meta.get('friendly_name', '')
        description = meta.get('description', '')
        ip_address = meta.get('ip_address', '') or _safe_get_if_addr(device_id)
        guid = _extract_guid(device_id)
        if guid and (not friendly or not description):
            reg_friendly, reg_desc = _lookup_windows_registry_adapter(guid)
            if not friendly and reg_friendly:
                friendly = reg_friendly
            if not description and reg_desc:
                description = reg_desc
        is_loopback = 'LOOPBACK' in device_id.upper()
        if not friendly and is_loopback:
            friendly = 'Npcap Loopback Adapter'
            if not description:
                description = 'Windows Loopback Capture Interface'
            if not ip_address:
                ip_address = '127.0.0.1'
        if not friendly and (not device_id.startswith('\\Device\\NPF_')):
            friendly = device_id
        if friendly:
            if description and description.lower() != friendly.lower():
                base_label = f'{friendly} ({description})'
            else:
                base_label = friendly
        elif description:
            base_label = description
        else:
            short_id = guid if guid else device_id
            base_label = f'Unidentified Adapter ({short_id})'
        if ip_address:
            display_label = f'{base_label} [{ip_address}]'
            is_available = True
        else:
            display_label = f'{base_label} [No IPv4 / Disconnected]'
            is_available = False
        resolved_items.append(NetworkInterfaceInfo(device_id=device_id, friendly_name=friendly or description or f'Unidentified ({guid or device_id})', description=description, ip_address=ip_address, display_label=display_label, is_available=is_available))
    seen_counts: Dict[str, int] = {}
    for item in resolved_items:
        seen_counts[item.display_label] = seen_counts.get(item.display_label, 0) + 1
    final_items: List[NetworkInterfaceInfo] = []
    for item in resolved_items:
        if seen_counts[item.display_label] > 1:
            guid_suffix = _extract_guid(item.device_id) or item.device_id
            unique_label = f'{item.display_label} — {guid_suffix}'
            final_items.append(NetworkInterfaceInfo(device_id=item.device_id, friendly_name=item.friendly_name, description=item.description, ip_address=item.ip_address, display_label=unique_label, is_available=item.is_available))
        else:
            final_items.append(item)
    return final_items

def suggest_default_interface_index(interfaces: List[str]) -> int:
    """
    Prefer Npcap's WSL virtual adapter index if present (preserving original behavior),
    otherwise default to 0.
    """
    for idx, name in enumerate(interfaces):
        if 'WSL' in name.upper():
            return idx
    return 0

def extract_initial_syn_packet(packet: Any) -> Optional[Tuple[str, int]]:
    """
    Inspect a captured packet and return (source_ip, destination_port) ONLY if it is
    an IPv4 initial TCP SYN packet (SYN = 1, ACK = 0).
    Supports both real Scapy Packet objects and lightweight test packet stubs.
    """
    if IP is not None and TCP is not None and hasattr(packet, 'haslayer'):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return None
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        src_ip = str(ip_layer.src)
        flags = int(tcp_layer.flags)
        dport = int(tcp_layer.dport)
    elif hasattr(packet, 'src_ip') and hasattr(packet, 'dport') and hasattr(packet, 'flags'):
        src_ip = str(packet.src_ip)
        flags = int(packet.flags)
        dport = int(packet.dport)
    else:
        return None
    if not flags & TCP_SYN_FLAG or flags & TCP_ACK_FLAG:
        return None
    return (src_ip, dport)

class PacketCaptureEngine:
    """Wraps Scapy AsyncSniffer with safe lifecycle management."""

    def __init__(self, sniffer_factory: Optional[Callable[..., Any]]=None, bpf_filter: str=CAPTURE_FILTER) -> None:
        self._sniffer_factory = sniffer_factory or AsyncSniffer
        self._bpf_filter = bpf_filter
        self._sniffer: Any = None
        self._active_interface: Optional[str] = None

    @property
    def is_capturing(self) -> bool:
        return self._sniffer is not None

    @property
    def active_interface(self) -> Optional[str]:
        return self._active_interface

    def start(self, interface: str, packet_callback: Callable[[Any], None]) -> None:
        if not interface or not str(interface).strip():
            raise ValueError('A valid network interface must be selected before starting packet capture.')
        if self._sniffer is not None:
            return
        if self._sniffer_factory is None:
            raise RuntimeError('Scapy AsyncSniffer is unavailable. Verify that Scapy and Npcap are installed.')
        sniffer = self._sniffer_factory(iface=interface, filter=self._bpf_filter, prn=packet_callback, store=False)
        sniffer.start()
        self._sniffer = sniffer
        self._active_interface = interface

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            finally:
                self._sniffer = None
                self._active_interface = None

@dataclass(frozen=True)
class DetectionAlert:
    """Emitted when a source IP reaches the unique destination TCP port threshold."""
    source_ip: str
    unique_ports: int
    scanned_ports: Tuple[int, ...]
    threshold: int
    window_seconds: int
    details: str

class PortScanDetector:
    """
    Tracks initial TCP SYN packets grouped by source IP over a rolling time window.
    Preserves exact threshold (15 unique ports) and rolling window (10 seconds) rules.
    """

    def __init__(self, port_threshold: int=PORT_THRESHOLD, window_seconds: int=WINDOW_SECONDS, clock: Optional[Callable[[], float]]=None) -> None:
        if port_threshold < 1:
            raise ValueError('port_threshold must be >= 1')
        if window_seconds <= 0:
            raise ValueError('window_seconds must be > 0')
        self.port_threshold = int(port_threshold)
        self.window_seconds = int(window_seconds)
        self._clock = clock or time.time
        self._lock = threading.RLock()
        self._port_events: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self._blocked_ips: Set[str] = set()
        self._pending_ips: Set[str] = set()

    def reset_session(self, preserve_blocked_ips: Optional[Set[str]]=None) -> None:
        """Reset per-investigation sliding windows while optionally retaining active firewall blocks."""
        with self._lock:
            self._port_events.clear()
            self._pending_ips.clear()
            if preserve_blocked_ips is not None:
                self._blocked_ips = set(preserve_blocked_ips)

    def sync_blocked_ips(self, blocked_ips: Set[str]) -> None:
        with self._lock:
            self._blocked_ips = set(blocked_ips)

    def mark_blocked(self, ip: str) -> None:
        with self._lock:
            self._pending_ips.discard(ip)
            self._blocked_ips.add(ip)

    def mark_unblocked(self, ip: str) -> None:
        with self._lock:
            self._blocked_ips.discard(ip)
            self._pending_ips.discard(ip)

    def clear_pending(self, ip: str) -> None:
        with self._lock:
            self._pending_ips.discard(ip)

    def get_blocked_ips(self) -> Set[str]:
        with self._lock:
            return set(self._blocked_ips)

    def get_pending_ips(self) -> Set[str]:
        with self._lock:
            return set(self._pending_ips)

    def get_activity(self, source_ip: str, timestamp: Optional[float]=None) -> Tuple[int, Tuple[int, ...]]:
        """Return the current rolling-window unique-port count and sorted ports for an IP."""
        now = float(timestamp) if timestamp is not None else float(self._clock())
        with self._lock:
            events = self._port_events.get(source_ip, deque())
            while events and now - events[0][0] > self.window_seconds:
                events.popleft()
            ports = tuple(sorted({port for _, port in events}))
            return (len(ports), ports)

    def observe_syn(self, source_ip: str, destination_port: int, timestamp: Optional[float]=None) -> Optional[DetectionAlert]:
        """
        Record an initial TCP SYN packet for (source_ip, destination_port).
        Returns a DetectionAlert once when unique destination ports in the rolling window
        reach self.port_threshold and the IP is not already blocked or pending.
        """
        now = float(timestamp) if timestamp is not None else float(self._clock())
        dport = int(destination_port)
        with self._lock:
            events = self._port_events[source_ip]
            events.append((now, dport))
            while events and now - events[0][0] > self.window_seconds:
                events.popleft()
            unique_ports = len({port for _, port in events})
            if unique_ports >= self.port_threshold and source_ip not in self._blocked_ips and (source_ip not in self._pending_ips):
                self._pending_ips.add(source_ip)
                return DetectionAlert(source_ip=source_ip, unique_ports=unique_ports, scanned_ports=tuple(sorted({port for _, port in events})), threshold=self.port_threshold, window_seconds=self.window_seconds, details=f'{self.port_threshold}+ unique TCP ports in {self.window_seconds}s')
        return None
