"""NetSentry | PortShield - services.py
Windows Defender Firewall operations (FirewallManager / FirewallWorker), the MonitoringEngine,
MonitoringService and HistoryService facades, and PDF / CSV reporting (ReportService).

Depends on database.py and detection.py.
"""
import csv
import io
import ipaddress
import math
import os
import queue
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from database import (
    APP_VERSION,
    DEFAULT_PAGE_SIZE,
    DETECTION_SCOPE_DISCLAIMER,
    FIREWALL_ACTION,
    FIREWALL_DIRECTION,
    FIREWALL_PROFILE,
    FIREWALL_PROTOCOL,
    FOOTER_DISCLAIMER,
    MAIN_TITLE,
    PORT_THRESHOLD,
    POWERSHELL_TIMEOUT_SECONDS,
    PRODUCT_NAME,
    PROJECT_NAME,
    PROTECTED_TARGET_IPS,
    RECENT_EVENTS_LIMIT,
    REPORTS_DIR,
    RULE_PREFIX,
    SUBTITLE,
    WINDOW_SECONDS,
    EventRepository,
    ScanRepository,
)
from detection import (
    NetworkInterfaceInfo,
    PacketCaptureEngine,
    PortScanDetector,
    check_capture_environment,
    extract_initial_syn_packet,
    is_windows_admin,
    list_detailed_network_interfaces,
    suggest_default_interface_index,
)

@dataclass(frozen=True)
class FirewallCommandResult:
    """Structured result of a Windows Defender Firewall operation."""
    status: str
    ip: str
    rule_name: str
    message: str

def run_powershell(command: str, timeout: int=POWERSHELL_TIMEOUT_SECONDS) -> subprocess.CompletedProcess:
    """Execute a non-interactive PowerShell command safely."""
    return subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command], capture_output=True, text=True, timeout=timeout)

class FirewallManager:
    """
    Manages inbound TCP block rules in Windows Defender Firewall.
    Strictly scoped to rules prefixed with RULE_PREFIX and enforces IP safety exclusions.
    """

    def __init__(self, rule_prefix: str=RULE_PREFIX, protected_ips: FrozenSet[str]=PROTECTED_TARGET_IPS, ps_runner: Callable[[str], subprocess.CompletedProcess]=run_powershell, admin_checker: Callable[[], bool]=is_windows_admin) -> None:
        self.rule_prefix = rule_prefix
        self.protected_ips = frozenset(protected_ips)
        self._ps_runner = ps_runner
        self._admin_checker = admin_checker

    def build_rule_name(self, ip: str) -> str:
        parsed = ipaddress.ip_address(str(ip).strip())
        sanitized = str(parsed).replace(':', '_').replace('.', '_')
        return f'{self.rule_prefix}{sanitized}'

    def is_owned_rule(self, rule_name: str) -> bool:
        return bool(rule_name) and rule_name.startswith(self.rule_prefix)

    def validate_target_ip(self, ip: str) -> Tuple[bool, str, str]:
        """
        Validate an IP address before creating any firewall rule.
        Returns (is_allowed, normalized_ip, reason).
        """
        try:
            parsed = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return (False, str(ip), 'Invalid IP address format')
        normalized = str(parsed)
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
            return (False, normalized, 'Unsafe/special address')
        if normalized in self.protected_ips:
            return (False, normalized, 'Configured Windows host target IP')
        return (True, normalized, 'Valid target IP')

    def block_ip(self, ip: str) -> FirewallCommandResult:
        """Create an inbound TCP block rule in Windows Defender Firewall for the given IP."""
        allowed, normalized_ip, reason = self.validate_target_ip(ip)
        safe_name = self.build_rule_name(normalized_ip) if reason != 'Invalid IP address format' else f'{self.rule_prefix}invalid'
        if not allowed:
            return FirewallCommandResult(status='SKIPPED', ip=normalized_ip, rule_name=safe_name, message=reason)
        if not self._admin_checker():
            return FirewallCommandResult(status='FAILED', ip=normalized_ip, rule_name=safe_name, message='Administrator privileges are required to create Windows Defender Firewall rules.')
        ps_script = f"$n='{safe_name}'; $ip='{normalized_ip}'; $existing=Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue; if (-not $existing) {{ New-NetFirewallRule -DisplayName $n -Direction {FIREWALL_DIRECTION} -Action {FIREWALL_ACTION} -RemoteAddress $ip -Protocol {FIREWALL_PROTOCOL} -Profile {FIREWALL_PROFILE} -Enabled True -ErrorAction Stop | Out-Null }}; Write-Output 'BLOCK_RULE_CREATED'"
        try:
            result = self._ps_runner(ps_script)
            if result.returncode == 0 and 'BLOCK_RULE_CREATED' in (result.stdout or ''):
                return FirewallCommandResult(status='BLOCKED', ip=normalized_ip, rule_name=safe_name, message='Windows Defender Firewall inbound TCP rule created')
            err = (result.stderr or result.stdout or 'Firewall command failed').strip()
            return FirewallCommandResult(status='FAILED', ip=normalized_ip, rule_name=safe_name, message=err[-500:])
        except Exception as exc:
            return FirewallCommandResult(status='FAILED', ip=normalized_ip, rule_name=safe_name, message=str(exc)[-500:])

    def unblock_ip(self, ip: str) -> FirewallCommandResult:
        """Remove an application-owned Windows Defender Firewall block rule for the given IP."""
        try:
            parsed = ipaddress.ip_address(str(ip).strip())
            normalized_ip = str(parsed)
        except ValueError:
            return FirewallCommandResult(status='FAILED', ip=str(ip), rule_name='', message='Invalid IP address format')
        safe_name = self.build_rule_name(normalized_ip)
        if not self.is_owned_rule(safe_name):
            return FirewallCommandResult(status='FAILED', ip=normalized_ip, rule_name=safe_name, message='Refused to modify firewall rule not owned by NetSentry PortShield.')
        if not self._admin_checker():
            return FirewallCommandResult(status='FAILED', ip=normalized_ip, rule_name=safe_name, message='Administrator privileges are required to remove Windows Defender Firewall rules.')
        ps_script = f"$n='{safe_name}'; $r=Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue; if ($r) {{$r | Remove-NetFirewallRule -ErrorAction Stop; Write-Output 'RULE_REMOVED'}} else {{Write-Output 'NO_RULE'}}"
        try:
            result = self._ps_runner(ps_script)
            stdout = (result.stdout or '').strip()
            if result.returncode == 0 and ('RULE_REMOVED' in stdout or 'NO_RULE' in stdout):
                return FirewallCommandResult(status='UNBLOCKED', ip=normalized_ip, rule_name=safe_name, message='Application-owned firewall rule removed or absent')
            err = (result.stderr or result.stdout or 'Unblock failed').strip()
            return FirewallCommandResult(status='FAILED', ip=normalized_ip, rule_name=safe_name, message=err[-500:])
        except Exception as exc:
            return FirewallCommandResult(status='FAILED', ip=normalized_ip, rule_name=safe_name, message=str(exc)[-500:])

    def list_live_owned_rules(self) -> List[str]:
        """Query Windows Defender Firewall for active rules created by this application."""
        if not self._admin_checker():
            return []
        ps_script = f"Get-NetFirewallRule -DisplayName '{self.rule_prefix}*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName"
        try:
            result = self._ps_runner(ps_script)
            if result.returncode != 0:
                return []
            return [line.strip() for line in (result.stdout or '').splitlines() if line.strip().startswith(self.rule_prefix)]
        except Exception:
            return []

@dataclass(frozen=True)
class BlockTask:
    """Queued automated block request produced by the packet detector."""
    scan_id: str
    source_ip: str
    unique_ports: int
    detection_event_id: Optional[int] = None
    scanned_ports: Tuple[int, ...] = tuple()

class FirewallWorker:
    """Consumes BlockTask items from a thread-safe queue and invokes FirewallManager."""

    def __init__(self, firewall_manager: FirewallManager, on_result: Callable[[BlockTask, FirewallCommandResult], None]) -> None:
        self._firewall_manager = firewall_manager
        self._on_result = on_result
        self._queue: 'queue.Queue[BlockTask]' = queue.Queue()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    @property
    def is_running(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()

    @property
    def pending_count(self) -> int:
        return self._queue.qsize()

    def enqueue(self, task: BlockTask) -> None:
        self._queue.put(task)

    def start(self) -> None:
        if self.is_running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, name='NetSentry-FirewallWorker', daemon=False)
        self._thread.start()

    def stop(self, drain_timeout: Optional[float]=None) -> bool:
        """Stop accepting work and drain every queued task before returning.

        The default is a complete drain (no timeout). FirewallManager applies a
        finite timeout to each PowerShell invocation, so queued work eventually
        completes. If a caller supplies a timeout and the worker is still alive,
        retain the thread reference so a new worker cannot be started alongside it.
        """
        self._running = False
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=drain_timeout)
        stopped = thread is None or not thread.is_alive()
        if stopped:
            self._thread = None
        return stopped

    def _run_loop(self) -> None:
        while self._running or not self._queue.empty():
            try:
                task = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                result = self._firewall_manager.block_ip(task.source_ip)
                self._on_result(task, result)
            except Exception as exc:
                fallback = FirewallCommandResult(status='FAILED', ip=task.source_ip, rule_name=self._firewall_manager.build_rule_name(task.source_ip), message=str(exc)[-500:])
                self._on_result(task, fallback)
            finally:
                self._queue.task_done()

class MonitoringEngine:
    """
    Coordinates live packet capture, TCP SYN port-scan detection, SQLite persistence,
    and asynchronous Windows Defender Firewall rule creation.
    """

    def __init__(self, scan_repo: ScanRepository, event_repo: EventRepository, firewall_manager: FirewallManager, capture_engine: Optional[PacketCaptureEngine]=None, detector: Optional[PortScanDetector]=None, admin_checker: Callable[[], bool]=is_windows_admin, port_threshold: int=PORT_THRESHOLD, window_seconds: int=WINDOW_SECONDS) -> None:
        self._scan_repo = scan_repo
        self._event_repo = event_repo
        self._firewall_manager = firewall_manager
        self._capture_engine = capture_engine or PacketCaptureEngine()
        self._detector = detector or PortScanDetector(port_threshold=port_threshold, window_seconds=window_seconds)
        self._admin_checker = admin_checker
        self._lock = threading.RLock()
        self._running = False
        self._current_scan_id: Optional[str] = None
        self._selected_interface: Optional[str] = None
        self._worker: Optional[FirewallWorker] = None
        self._normal_activity_logged: Dict[str, Tuple[int, ...]] = {}
        active_rules = self._event_repo.get_active_blocked_rules()
        self._detector.sync_blocked_ips({r['source_ip'] for r in active_rules})

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._running

    @property
    def current_scan_id(self) -> Optional[str]:
        with self._lock:
            return self._current_scan_id

    @property
    def selected_interface(self) -> Optional[str]:
        with self._lock:
            return self._selected_interface

    @property
    def detector(self) -> PortScanDetector:
        return self._detector

    def start(self, interface: str) -> str:
        """Start a new investigation session on the specified network interface."""
        if not interface or not str(interface).strip():
            raise ValueError('No network interface selected. Please select a network interface before starting network monitoring.')
        with self._lock:
            if self._running:
                return self._current_scan_id or ''
            if self._worker is not None and self._worker.is_running:
                raise RuntimeError('The previous firewall worker is still shutting down. Please wait before starting another investigation.')
            if not self._admin_checker():
                raise PermissionError('Administrator privileges are required to manage Windows Defender Firewall.')
            active_rules = self._event_repo.get_active_blocked_rules()
            self._detector.reset_session(preserve_blocked_ips={r['source_ip'] for r in active_rules})
            self._normal_activity_logged.clear()
            investigation = self._scan_repo.create_investigation(network_interface=interface, threshold=self._detector.port_threshold, window_seconds=self._detector.window_seconds)
            scan_id = investigation['scan_id']
            self._current_scan_id = scan_id
            self._selected_interface = interface
            self._running = True
            self._worker = FirewallWorker(firewall_manager=self._firewall_manager, on_result=self._handle_firewall_result)
            self._worker.start()
            try:
                self._capture_engine.start(interface=interface, packet_callback=self.process_packet)
            except Exception:
                self._running = False
                if self._worker:
                    self._worker.stop()
                    self._worker = None
                self._scan_repo.complete_investigation(scan_id, status='FAILED')
                raise
            return scan_id

    def stop(self) -> Optional[Dict[str, Any]]:
        """Safely stop packet capture, drain firewall worker, and finalize investigation record."""
        with self._lock:
            if not self._running and (not self._capture_engine.is_capturing):
                return None
            self._running = False
            scan_id = self._current_scan_id
            worker = self._worker
        self._capture_engine.stop()
        if worker is not None:
            worker.stop()
            with self._lock:
                if self._worker is worker:
                    self._worker = None
        if scan_id:
            return self._scan_repo.complete_investigation(scan_id, status='COMPLETED')
        return None

    def reset_current_session(self) -> None:
        """Clear the UI-facing current session pointer after a completed investigation."""
        with self._lock:
            if self._running:
                raise RuntimeError('Stop monitoring before starting a new investigation.')
            self._current_scan_id = None
            self._selected_interface = None
            self._normal_activity_logged.clear()
            self._detector.reset_session(preserve_blocked_ips={r['source_ip'] for r in self._event_repo.get_active_blocked_rules()})

    def process_packet(self, packet: Any) -> None:
        """Process a captured packet through the TCP SYN detector."""
        try:
            parsed = extract_initial_syn_packet(packet)
            if parsed is None:
                return
            src_ip, dport = parsed
            alert = self._detector.observe_syn(src_ip, dport)
            with self._lock:
                scan_id = self._current_scan_id
            if not scan_id:
                return
            if alert is None:
                if src_ip in self._detector.get_blocked_ips() or src_ip in self._detector.get_pending_ips():
                    return
                current_count, current_ports = self._detector.get_activity(src_ip)
                previous_ports = self._normal_activity_logged.get(src_ip, tuple())
                if 0 < current_count < self._detector.port_threshold and current_ports != previous_ports:
                    self._event_repo.record_event(scan_id=scan_id, event_type='NORMAL TRAFFIC', source_ip=src_ip, unique_ports=current_count, detection_details=f"Below detection threshold ({current_count}/{self._detector.port_threshold} unique TCP ports in the active window). Scanned destination ports: {', '.join((str(port) for port in current_ports))}", firewall_status='INFORMATIONAL', additional_info='Observed activity remains below the configured port-scan threshold.')
                    self._normal_activity_logged[src_ip] = tuple(current_ports)
                return
            rule_name = self._firewall_manager.build_rule_name(alert.source_ip)
            event_id = self._event_repo.record_event(scan_id=scan_id, event_type='DETECTED - BLOCK PENDING', source_ip=alert.source_ip, unique_ports=alert.unique_ports, detection_details=f"{alert.details}. Scanned destination ports: {', '.join((str(port) for port in alert.scanned_ports))}", firewall_status='PENDING', related_firewall_rule=rule_name, additional_info=f"Threshold {alert.threshold} ports in {alert.window_seconds}s reached; observed ports: {', '.join((str(port) for port in alert.scanned_ports))}")
            task = BlockTask(scan_id=scan_id, source_ip=alert.source_ip, unique_ports=alert.unique_ports, detection_event_id=event_id, scanned_ports=tuple(alert.scanned_ports))
            with self._lock:
                if self._worker is not None:
                    self._worker.enqueue(task)
                else:
                    result = self._firewall_manager.block_ip(alert.source_ip)
                    self._handle_firewall_result(task, result)
        except Exception as exc:
            with self._lock:
                scan_id = self._current_scan_id
            if scan_id:
                try:
                    self._event_repo.record_event(scan_id=scan_id, event_type='CAPTURE ERROR', source_ip='-', unique_ports=0, detection_details=str(exc)[:300], firewall_status='INFORMATIONAL')
                except Exception:
                    pass

    def _handle_firewall_result(self, task: BlockTask, result: FirewallCommandResult) -> None:
        """Persist firewall outcome and update detector state."""
        now_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if result.status == 'BLOCKED':
            self._detector.mark_blocked(task.source_ip)
            self._event_repo.record_event(scan_id=task.scan_id, event_type='BLOCKED', source_ip=task.source_ip, unique_ports=task.unique_ports, detection_details=result.message + '. Scanned destination ports: ' + ', '.join(map(str, task.scanned_ports)) if task.scanned_ports else result.message, firewall_status='SUCCESSFUL', related_firewall_rule=result.rule_name, timestamp=now_ts)
            self._event_repo.record_firewall_rule(scan_id=task.scan_id, source_ip=task.source_ip, rule_name=result.rule_name, status='ACTIVE', created_at=now_ts, related_event_id=task.detection_event_id)
        elif result.status == 'SKIPPED':
            self._detector.clear_pending(task.source_ip)
            self._event_repo.record_event(scan_id=task.scan_id, event_type='BLOCK SKIPPED', source_ip=task.source_ip, unique_ports=task.unique_ports, detection_details=result.message + '. Scanned destination ports: ' + ', '.join(map(str, task.scanned_ports)) if task.scanned_ports else result.message, firewall_status='SKIPPED', related_firewall_rule=result.rule_name, timestamp=now_ts)
            self._event_repo.record_firewall_rule(scan_id=task.scan_id, source_ip=task.source_ip, rule_name=result.rule_name, status='SKIPPED', created_at=now_ts, failure_info=result.message, related_event_id=task.detection_event_id)
        else:
            self._detector.clear_pending(task.source_ip)
            self._event_repo.record_event(scan_id=task.scan_id, event_type='BLOCK FAILED', source_ip=task.source_ip, unique_ports=task.unique_ports, detection_details=result.message + '. Scanned destination ports: ' + ', '.join(map(str, task.scanned_ports)) if task.scanned_ports else result.message, firewall_status='FAILED', related_firewall_rule=result.rule_name, timestamp=now_ts)
            self._event_repo.record_firewall_rule(scan_id=task.scan_id, source_ip=task.source_ip, rule_name=result.rule_name, status='FAILED', created_at=now_ts, failure_info=result.message, related_event_id=task.detection_event_id)

    def manual_unblock(self, ip: str) -> FirewallCommandResult:
        """Manually remove an application-owned firewall block rule and log the action."""
        result = self._firewall_manager.unblock_ip(ip)
        now_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if result.status == 'UNBLOCKED':
            self._detector.mark_unblocked(result.ip)
            self._normal_activity_logged.pop(result.ip, None)
            self._event_repo.mark_firewall_rule_removed(result.rule_name, removed_at=now_ts)
            with self._lock:
                scan_id = self._current_scan_id
            if not scan_id:
                recent = self._scan_repo.list_investigations(limit=1)
                if recent:
                    scan_id = recent[0]['scan_id']
                else:
                    created = self._scan_repo.create_investigation(network_interface='Manual Firewall Action')
                    scan_id = created['scan_id']
                    self._scan_repo.complete_investigation(scan_id, status='COMPLETED')
            self._event_repo.record_event(scan_id=scan_id, event_type='UNBLOCKED', source_ip=result.ip, unique_ports=0, detection_details=result.message, firewall_status='UNBLOCKED', related_firewall_rule=result.rule_name, timestamp=now_ts)
        return result

class HistoryService:
    """Provides search, filtering, pagination, inspection, and CSV export over SQLite history."""

    def __init__(self, scan_repo: ScanRepository, event_repo: EventRepository) -> None:
        self._scan_repo = scan_repo
        self._event_repo = event_repo

    def get_history_kpis(self) -> Dict[str, Any]:
        metrics = self._scan_repo.get_all_time_metrics()
        return {'total_investigations': metrics['total_investigations'], 'total_detection_events': metrics['total_events'], 'successful_firewall_blocks': metrics['successful_blocks'], 'failed_firewall_actions': metrics['block_failures'], 'last_recorded_activity': metrics['last_activity']}

    def search_history(self, scan_id_query: str='', source_ip_query: str='', start_date: Optional[str]=None, end_date: Optional[str]=None, event_type: str='ALL', firewall_status: str='ALL', sort_order: str='NEWEST', page: int=1, page_size: int=DEFAULT_PAGE_SIZE) -> Dict[str, Any]:
        rows, total_count = self._event_repo.query_history(scan_id_query=scan_id_query, source_ip_query=source_ip_query, start_date=start_date, end_date=end_date, event_type=event_type, firewall_status=firewall_status, sort_order=sort_order, page=page, page_size=page_size)
        total_pages = max(1, math.ceil(total_count / max(1, page_size)))
        return {'items': rows, 'total_count': total_count, 'page': min(max(1, page), total_pages), 'page_size': page_size, 'total_pages': total_pages}

    def get_investigation_details(self, scan_id: str) -> Optional[Dict[str, Any]]:
        investigation = self._scan_repo.get_investigation(scan_id)
        if not investigation:
            return None
        events = self._event_repo.get_events_for_scan(scan_id)
        rules = self._event_repo.get_rules_for_scan(scan_id)
        unique_ips = sorted({e['source_ip'] for e in events if e.get('source_ip') and e['source_ip'] not in ('-', '')})
        max_ports = max([int(e.get('unique_ports') or 0) for e in events], default=0)
        return {'investigation': investigation, 'events': events, 'firewall_rules': rules, 'unique_source_ips': unique_ips, 'max_unique_ports': max_ports}

    def export_all_events_csv(self) -> str:
        """Export all recorded security events across all investigations as CSV text."""
        investigations = self._scan_repo.list_investigations(limit=10000)
        all_events: List[Dict[str, Any]] = []
        for inv in investigations:
            all_events.extend(self._event_repo.get_events_for_scan(inv['scan_id']))
        all_events.sort(key=lambda r: (r.get('timestamp', ''), r.get('event_id', 0)), reverse=True)
        return '# Export Scope: ALL investigation history (unfiltered)\n' + self._serialize_events_csv(all_events)

    def export_filtered_history_csv(self, scan_id_query: str='', source_ip_query: str='', start_date: Optional[str]=None, end_date: Optional[str]=None, event_type: str='ALL', firewall_status: str='ALL', sort_order: str='NEWEST') -> str:
        """Export matching investigation history records as CSV text."""
        rows, _ = self._event_repo.query_history(scan_id_query=scan_id_query, source_ip_query=source_ip_query, start_date=start_date, end_date=end_date, event_type=event_type, firewall_status=firewall_status, sort_order=sort_order, page=1, page_size=100000)
        output = io.StringIO()
        output.write('# Export Scope: FILTERED investigation history\n')
        output.write(f"# Scan ID filter: {scan_id_query or 'None'}\n")
        output.write(f"# Source IP filter: {source_ip_query or 'None'}\n")
        output.write(f"# Start date: {start_date or 'None'}\n")
        output.write(f"# End date: {end_date or 'None'}\n")
        output.write(f'# Event type: {event_type}\n')
        output.write(f'# Firewall status: {firewall_status}\n')
        output.write(f'# Sort order: {sort_order}\n')
        fieldnames = ['scan_id', 'event_ids', 'timestamp', 'end_time', 'investigation_status', 'network_interface', 'source_ips', 'event_count', 'max_unique_ports', 'successful_blocks', 'pending_blocks', 'failed_blocks', 'skipped_blocks', 'latest_firewall_status', 'latest_details']
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        return output.getvalue()

    @staticmethod
    def _serialize_events_csv(events: List[Dict[str, Any]]) -> str:
        output = io.StringIO()
        fieldnames = ['event_id', 'scan_id', 'timestamp', 'event', 'source_ip', 'unique_ports', 'firewall_status', 'related_firewall_rule', 'details']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for ev in events:
            writer.writerow({'event_id': f"EVT-{int(ev.get('event_id') or 0):06d}", 'scan_id': ev.get('scan_id', ''), 'timestamp': ev.get('timestamp', ''), 'event': ev.get('event_type', ''), 'source_ip': ev.get('source_ip', ''), 'unique_ports': ev.get('unique_ports', 0), 'firewall_status': ev.get('firewall_status', ''), 'related_firewall_rule': ev.get('related_firewall_rule') or '', 'details': ev.get('detection_details') or ''})
        return output.getvalue()

class MonitoringService:
    """Facade exposing clean operations for the Investigate and Dashboard UI layers."""

    def __init__(self, engine: MonitoringEngine, scan_repo: ScanRepository, event_repo: EventRepository) -> None:
        self._engine = engine
        self._scan_repo = scan_repo
        self._event_repo = event_repo

    @property
    def is_running(self) -> bool:
        return self._engine.is_running

    @property
    def current_scan_id(self) -> Optional[str]:
        return self._engine.current_scan_id

    @property
    def selected_interface(self) -> Optional[str]:
        return self._engine.selected_interface

    def get_detection_rule_config(self) -> Dict[str, Any]:
        return {'port_threshold': self._engine.detector.port_threshold, 'window_seconds': self._engine.detector.window_seconds, 'protocol': 'TCP', 'packet_criteria': 'Initial TCP SYN packets (SYN = 1, ACK = 0) grouped by source IP'}

    def get_environment_status(self) -> Dict[str, Any]:
        admin_ok = is_windows_admin()
        capture_ok, capture_msg = check_capture_environment()
        detailed_interfaces: List[NetworkInterfaceInfo] = list_detailed_network_interfaces()
        raw_interfaces = [item.device_id for item in detailed_interfaces]
        interface_label_map = {item.device_id: item.display_label for item in detailed_interfaces}
        default_idx = suggest_default_interface_index(raw_interfaces) if raw_interfaces else 0
        return {'is_admin': admin_ok, 'capture_ready': capture_ok, 'capture_message': capture_msg, 'interfaces': raw_interfaces, 'interface_details': detailed_interfaces, 'interface_label_map': interface_label_map, 'suggested_interface_index': default_idx, 'project_name': PROJECT_NAME, 'product_name': PRODUCT_NAME, 'version': APP_VERSION}

    def start_monitoring(self, interface: str) -> str:
        return self._engine.start(interface)

    def stop_monitoring(self) -> Optional[Dict[str, Any]]:
        return self._engine.stop()

    def reset_current_session(self) -> None:
        self._engine.reset_current_session()

    def get_investigation_details(self, scan_id: Optional[str]) -> Optional[Dict[str, Any]]:
        return self._scan_repo.get_investigation(scan_id) if scan_id else None

    def get_events_for_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        return self._event_repo.get_events_for_scan(scan_id)

    def get_current_session_overview_for(self, scan_id: str) -> Dict[str, Any]:
        return self._scan_repo.get_session_overview(scan_id)

    def unblock_ip(self, ip: str) -> FirewallCommandResult:
        return self._engine.manual_unblock(ip)

    def get_current_session_overview(self) -> Dict[str, Any]:
        scan_id = self._engine.current_scan_id
        overview = self._scan_repo.get_session_overview(scan_id)
        live_pending = len(self._engine.detector.get_pending_ips())
        overview['pending_blocks'] = max(int(overview.get('pending_blocks', 0)), live_pending)
        overview['scan_id'] = scan_id
        overview['is_running'] = self._engine.is_running
        overview['selected_interface'] = self._engine.selected_interface
        return overview

    def get_recent_session_events(self, limit: int=RECENT_EVENTS_LIMIT) -> List[Dict[str, Any]]:
        scan_id = self._engine.current_scan_id
        if not scan_id:
            return []
        return self._event_repo.get_recent_events(scan_id=scan_id, limit=limit)

    def get_active_blocked_rules(self) -> List[Dict[str, Any]]:
        return self._event_repo.get_active_blocked_rules()

    def get_managed_firewall_rules(self, limit: int=200) -> List[Dict[str, Any]]:
        return self._event_repo.get_all_managed_rules(limit=limit)

    def get_firewall_rule_details(self, rule_id: int) -> Optional[Dict[str, Any]]:
        return self._event_repo.get_rule_by_id(rule_id)

    def get_dashboard_snapshot(self) -> Dict[str, Any]:
        """Return all-time dashboard data directly from SQLite."""
        metrics = self._scan_repo.get_all_time_metrics()
        events = self._event_repo.get_all_events(limit=5000)
        investigations = self._scan_repo.list_investigations(limit=5000)
        firewall_rules = self._event_repo.get_all_managed_rules(limit=5000)
        active_rules = self._event_repo.get_active_blocked_rules()
        live_pending = len(self._engine.detector.get_pending_ips())
        metrics['pending_blocks'] = max(int(metrics.get('pending_blocks', 0)), live_pending)
        successful_blocked_ips = sorted({str(ev.get('source_ip')) for ev in events if ev.get('event_type') == 'BLOCKED' and ev.get('firewall_status') == 'SUCCESSFUL' and (ev.get('source_ip') not in (None, '', '-'))})
        metrics['successful_blocks'] = len(successful_blocked_ips)
        normal_events = []
        malicious_events = []
        for ev in events:
            event_type = str(ev.get('event_type', '')).upper()
            if event_type in {'NORMAL', 'NORMAL TRAFFIC', 'BELOW THRESHOLD', 'NORMAL ACTIVITY'}:
                ev['classification'] = 'NORMAL'
                normal_events.append(ev)
            elif event_type.startswith(('DETECTED', 'BLOCKED', 'BLOCK FAILED', 'BLOCK SKIPPED')):
                ev['classification'] = 'MALICIOUS / THRESHOLD REACHED'
                malicious_events.append(ev)
            else:
                ev['classification'] = 'FIREWALL / SYSTEM ACTIVITY'
        return {'metrics': metrics, 'events': events, 'investigations': investigations, 'firewall_rules': firewall_rules, 'active_blocked_rules': active_rules, 'successful_blocked_ips': successful_blocked_ips, 'normal_events': normal_events, 'malicious_events': malicious_events}

NAVY_DARK = colors.HexColor('#070d1f')

NAVY_SURFACE = colors.HexColor('#0f172a')

NAVY_ALT = colors.HexColor('#16223b')

ELECTRIC_BLUE = colors.HexColor('#2563eb')

CYAN_ACCENT = colors.HexColor('#06b6d4')

GREEN_OK = colors.HexColor('#10b981')

AMBER_WARN = colors.HexColor('#f59e0b')

RED_ALERT = colors.HexColor('#ef4444')

SLATE_BORDER = colors.HexColor('#cbd5e1')

SLATE_LIGHT = colors.HexColor('#f1f5f9')

TEXT_DARK = colors.HexColor('#0f172a')

TEXT_MUTED = colors.HexColor('#475569')

def _safe_text(value: Any, fallback: str='Not Available') -> str:
    if value is None:
        return fallback
    s = str(value).strip()
    return s if s else fallback

def _escape_xml(text: str) -> str:
    return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

class ReportService:
    """Generates multi-section ReportLab technical PDF reports from SQLite investigation records."""

    def __init__(self, scan_repo: ScanRepository, event_repo: EventRepository, reports_dir: str=REPORTS_DIR) -> None:
        self._scan_repo = scan_repo
        self._event_repo = event_repo
        self._reports_dir = reports_dir
        os.makedirs(self._reports_dir, exist_ok=True)

    def generate_investigation_pdf_bytes(self, scan_id: str) -> bytes:
        """Build a complete 8-section PDF investigation report and return raw PDF bytes."""
        investigation = self._scan_repo.get_investigation(scan_id)
        if not investigation:
            raise ValueError(f'Investigation record not found for Scan ID: {scan_id}')
        events = self._event_repo.get_events_for_scan(scan_id)
        rules = self._event_repo.get_rules_for_scan(scan_id)
        generated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=22 * mm, bottomMargin=22 * mm, title=f'{PROJECT_NAME} {PRODUCT_NAME} - Investigation Report ({scan_id})', author=f'{PROJECT_NAME} {PRODUCT_NAME} {APP_VERSION}')
        styles = self._build_styles()
        story = self._build_story(investigation=investigation, events=events, rules=rules, generated_at=generated_at, styles=styles)

        def on_cover_page(canvas_obj, doc_obj):
            self._draw_cover_backdrop(canvas_obj, doc_obj, scan_id, generated_at)

        def on_later_pages(canvas_obj, doc_obj):
            self._draw_header_and_footer(canvas_obj, doc_obj, scan_id, generated_at)
        doc.build(story, onFirstPage=on_cover_page, onLaterPages=on_later_pages)
        return buffer.getvalue()

    def save_investigation_pdf(self, scan_id: str, filename: Optional[str]=None) -> str:
        """Generate and persist the investigation PDF into the reports/ directory."""
        pdf_bytes = self.generate_investigation_pdf_bytes(scan_id)
        safe_scan = scan_id.replace('/', '_').replace('\\', '_')
        out_name = filename or f'{PROJECT_NAME}_{PRODUCT_NAME}_{safe_scan}.pdf'
        out_path = os.path.join(self._reports_dir, out_name)
        with open(out_path, 'wb') as f:
            f.write(pdf_bytes)
        return out_path

    @staticmethod
    def _extract_ports(details: Any) -> str:
        import re
        match = re.search('Scanned destination ports:\\s*([0-9, ]+)', str(details or ''), re.IGNORECASE)
        if not match:
            match = re.search('observed ports:\\s*([0-9, ]+)', str(details or ''), re.IGNORECASE)
        if not match:
            return '—'
        ports = sorted({int(value) for value in re.findall('\\d+', match.group(1))})
        return ', '.join(map(str, ports)) if ports else '—'

    def _build_styles(self) -> Dict[str, ParagraphStyle]:
        base = getSampleStyleSheet()
        return {'cover_brand': ParagraphStyle('CoverBrand', parent=base['Title'], fontName='Helvetica-Bold', fontSize=28, leading=34, textColor=colors.white, alignment=TA_LEFT, spaceAfter=4), 'cover_product': ParagraphStyle('CoverProduct', parent=base['Heading2'], fontName='Helvetica-Bold', fontSize=15, leading=20, textColor=CYAN_ACCENT, alignment=TA_LEFT, spaceAfter=10), 'cover_title': ParagraphStyle('CoverTitle', parent=base['Heading1'], fontName='Helvetica-Bold', fontSize=20, leading=26, textColor=colors.white, alignment=TA_LEFT, spaceAfter=8), 'cover_sub': ParagraphStyle('CoverSub', parent=base['Normal'], fontName='Helvetica', fontSize=11, leading=16, textColor=colors.HexColor('#cbd5e1'), alignment=TA_LEFT, spaceAfter=18), 'section_h1': ParagraphStyle('SectionH1', parent=base['Heading1'], fontName='Helvetica-Bold', fontSize=14, leading=19, textColor=NAVY_DARK, spaceBefore=12, spaceAfter=6), 'section_h2': ParagraphStyle('SectionH2', parent=base['Heading2'], fontName='Helvetica-Bold', fontSize=11, leading=15, textColor=ELECTRIC_BLUE, spaceBefore=8, spaceAfter=4), 'body': ParagraphStyle('BodyTextSOC', parent=base['Normal'], fontName='Helvetica', fontSize=9.5, leading=14, textColor=TEXT_DARK, spaceAfter=6), 'muted': ParagraphStyle('MutedSOC', parent=base['Normal'], fontName='Helvetica', fontSize=8.5, leading=12, textColor=TEXT_MUTED, spaceAfter=4), 'table_cell': ParagraphStyle('TableCell', parent=base['Normal'], fontName='Helvetica', fontSize=8, leading=10.5, textColor=TEXT_DARK), 'table_header': ParagraphStyle('TableHeader', parent=base['Normal'], fontName='Helvetica-Bold', fontSize=8, leading=10.5, textColor=colors.white), 'table_cell_compact': ParagraphStyle('TableCellCompact', parent=base['Normal'], fontName='Helvetica', fontSize=7.2, leading=9, textColor=TEXT_DARK, wordWrap='CJK'), 'table_header_compact': ParagraphStyle('TableHeaderCompact', parent=base['Normal'], fontName='Helvetica-Bold', fontSize=7.2, leading=9, textColor=colors.white, wordWrap='CJK')}

    def _draw_3d_shield_emblem(self, c, x: float, y: float, scale: float=1.0) -> None:
        """Render a layered 3D-shaded vector cybersecurity shield emblem on the PDF canvas."""
        c.saveState()
        c.translate(x, y)
        c.scale(scale, scale)
        p_shadow = c.beginPath()
        p_shadow.moveTo(26, 56)
        p_shadow.lineTo(50, 46)
        p_shadow.lineTo(46, 18)
        p_shadow.lineTo(26, 2)
        p_shadow.lineTo(6, 18)
        p_shadow.lineTo(2, 46)
        p_shadow.close()
        c.setFillColor(colors.HexColor('#06132b'))
        c.drawPath(p_shadow, fill=1, stroke=0)
        p_left = c.beginPath()
        p_left.moveTo(24, 58)
        p_left.lineTo(24, 4)
        p_left.lineTo(4, 20)
        p_left.lineTo(0, 48)
        p_left.close()
        c.setFillColor(ELECTRIC_BLUE)
        c.drawPath(p_left, fill=1, stroke=0)
        p_right = c.beginPath()
        p_right.moveTo(24, 58)
        p_right.lineTo(48, 48)
        p_right.lineTo(44, 20)
        p_right.lineTo(24, 4)
        p_right.close()
        c.setFillColor(CYAN_ACCENT)
        c.drawPath(p_right, fill=1, stroke=0)
        p_core = c.beginPath()
        p_core.moveTo(24, 51)
        p_core.lineTo(41, 43)
        p_core.lineTo(38, 22)
        p_core.lineTo(24, 10)
        p_core.lineTo(10, 22)
        p_core.lineTo(7, 43)
        p_core.close()
        c.setFillColor(NAVY_DARK)
        c.setStrokeColor(colors.HexColor('#7dd3fc'))
        c.setLineWidth(1.0)
        c.drawPath(p_core, fill=1, stroke=1)
        c.setStrokeColor(colors.white)
        c.setLineWidth(2.2)
        c.line(16, 31, 22, 24)
        c.line(22, 24, 33, 38)
        c.restoreState()

    def _draw_cover_backdrop(self, c, doc, scan_id: str, generated_at: str) -> None:
        """Draw dark SOC cover header banner, 3D shield emblem, and cover page footer."""
        width, height = A4
        c.saveState()
        c.setFillColor(NAVY_DARK)
        c.rect(0, height - 102 * mm, width, 102 * mm, fill=1, stroke=0)
        c.setFillColor(CYAN_ACCENT)
        c.rect(0, height - 104 * mm, width, 2 * mm, fill=1, stroke=0)
        self._draw_3d_shield_emblem(c, width - 48 * mm, height - 48 * mm, scale=1.15)
        c.setStrokeColor(SLATE_BORDER)
        c.setLineWidth(0.6)
        c.line(18 * mm, 16 * mm, width - 18 * mm, 16 * mm)
        c.setFont('Helvetica', 7.5)
        c.setFillColor(TEXT_MUTED)
        c.drawString(18 * mm, 11 * mm, f'{PROJECT_NAME} | {PRODUCT_NAME} | {APP_VERSION} — Technical Security Investigation Report')
        c.drawRightString(width - 18 * mm, 11 * mm, f'Page {doc.page}')
        c.restoreState()

    def _draw_header_and_footer(self, c, doc, scan_id: str, generated_at: str) -> None:
        """Section 8: Running header and Report Footer with page numbers on content pages."""
        width, height = A4
        c.saveState()
        c.setFillColor(NAVY_DARK)
        c.rect(0, height - 14 * mm, width, 14 * mm, fill=1, stroke=0)
        c.setFont('Helvetica-Bold', 8.5)
        c.setFillColor(colors.white)
        c.drawString(18 * mm, height - 9 * mm, f'{PROJECT_NAME} | {PRODUCT_NAME} ({APP_VERSION})')
        c.setFont('Helvetica', 8)
        c.setFillColor(CYAN_ACCENT)
        c.drawRightString(width - 18 * mm, height - 9 * mm, f'Scan ID: {scan_id}')
        c.setStrokeColor(SLATE_BORDER)
        c.setLineWidth(0.6)
        c.line(18 * mm, 16 * mm, width - 18 * mm, 16 * mm)
        c.setFont('Helvetica', 7.5)
        c.setFillColor(TEXT_MUTED)
        c.drawString(18 * mm, 11.5 * mm, f'{PROJECT_NAME} | {PRODUCT_NAME} | {APP_VERSION}  •  Generated: {generated_at}')
        c.drawRightString(width - 18 * mm, 11.5 * mm, f'Page {doc.page}')
        c.setFont('Helvetica-Oblique', 7)
        c.drawString(18 * mm, 7.5 * mm, FOOTER_DISCLAIMER)
        c.restoreState()

    def _build_story(self, investigation: Dict[str, Any], events: List[Dict[str, Any]], rules: List[Dict[str, Any]], generated_at: str, styles: Dict[str, ParagraphStyle]) -> List[Any]:
        story: List[Any] = []
        scan_id = _safe_text(investigation.get('scan_id'))
        threshold = int(investigation.get('detection_threshold') or PORT_THRESHOLD)
        window_sec = int(investigation.get('detection_window_seconds') or WINDOW_SECONDS)
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph(f'{PROJECT_NAME}', styles['cover_brand']))
        story.append(Paragraph(f'{PRODUCT_NAME} &nbsp;|&nbsp; {APP_VERSION}', styles['cover_product']))
        story.append(Paragraph('Technical Security Investigation Report', styles['cover_title']))
        story.append(Paragraph(f'{MAIN_TITLE} — {SUBTITLE}', styles['cover_sub']))
        story.append(Spacer(1, 28 * mm))
        cover_meta_raw = [['Report Field', 'Recorded Investigation Value'], ['Project / Product', f'{PROJECT_NAME} — {PRODUCT_NAME} ({APP_VERSION})'], ['Investigation Scan ID', scan_id], ['Investigation Status', _safe_text(investigation.get('status'))], ['Capture Network Interface', _safe_text(investigation.get('network_interface'))], ['Investigation Start Time', _safe_text(investigation.get('start_time'))], ['Investigation End Time', _safe_text(investigation.get('end_time'), 'Active / Not yet ended')], ['Report Generated Timestamp', generated_at], ['Configured Detection Rule', f'{threshold} unique TCP destination ports within {window_sec} seconds']]
        cover_meta = [[Paragraph(_escape_xml(str(cell)), styles['table_header'] if row_idx == 0 else styles['table_cell']) for cell in row] for row_idx, row in enumerate(cover_meta_raw)]
        cover_tbl = Table(cover_meta, colWidths=[62 * mm, 112 * mm], repeatRows=1, splitByRow=1)
        cover_tbl.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), NAVY_DARK), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white), ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('FONTSIZE', (0, 0), (-1, -1), 9.5), ('BACKGROUND', (0, 1), (0, -1), SLATE_LIGHT), ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'), ('TEXTCOLOR', (0, 1), (-1, -1), TEXT_DARK), ('GRID', (0, 0), (-1, -1), 0.5, SLATE_BORDER), ('TOPPADDING', (0, 0), (-1, -1), 7), ('BOTTOMPADDING', (0, 0), (-1, -1), 7), ('LEFTPADDING', (0, 0), (-1, -1), 8)]))
        story.append(cover_tbl)
        story.append(Spacer(1, 10 * mm))
        story.append(Paragraph(f'<i>{_escape_xml(FOOTER_DISCLAIMER)}</i>', styles['muted']))
        story.append(PageBreak())
        story.append(Paragraph('1. Investigation Summary', styles['section_h1']))
        story.append(Paragraph('This section summarizes the recorded lifecycle, capture interface, and aggregate outcome metrics stored in SQLite for this investigation session.', styles['body']))
        summary_data = [['Metric', 'Recorded Value', 'Metric', 'Recorded Value'], ['Scan ID', scan_id, 'Status', _safe_text(investigation.get('status'))], ['Start Timestamp', _safe_text(investigation.get('start_time')), 'End Timestamp', _safe_text(investigation.get('end_time'), 'Active / Not Recorded')], ['Network Interface', _safe_text(investigation.get('network_interface')), 'Total Recorded Events', str(int(investigation.get('total_events') or 0))], ['Unique Source IPs', str(int(investigation.get('unique_source_ips') or 0)), 'Successful Firewall Blocks', str(int(investigation.get('successful_blocks') or 0))], ['Blocks Pending', str(int(investigation.get('pending_blocks') or 0)), 'Block Failures / Skipped', f"{int(investigation.get('failed_blocks') or 0)} failed / {int(investigation.get('skipped_blocks') or 0)} skipped"]]
        summary_data = [[Paragraph(_escape_xml(str(cell)), styles['table_header'] if row_idx == 0 else styles['table_cell']) for cell in row] for row_idx, row in enumerate(summary_data)]
        summary_tbl = Table(summary_data, colWidths=[42 * mm, 45 * mm, 44 * mm, 43 * mm], repeatRows=1, splitByRow=1)
        summary_tbl.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), ELECTRIC_BLUE), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white), ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'), ('FONTNAME', (2, 1), (2, -1), 'Helvetica-Bold'), ('BACKGROUND', (0, 1), (0, -1), SLATE_LIGHT), ('BACKGROUND', (2, 1), (2, -1), SLATE_LIGHT), ('FONTSIZE', (0, 0), (-1, -1), 8.5), ('GRID', (0, 0), (-1, -1), 0.5, SLATE_BORDER), ('TOPPADDING', (0, 0), (-1, -1), 6), ('BOTTOMPADDING', (0, 0), (-1, -1), 6), ('LEFTPADDING', (0, 0), (-1, -1), 6)]))
        story.append(summary_tbl)
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph('2. Detection Details', styles['section_h1']))
        story.append(Paragraph(f'Detection Criteria: Initial TCP SYN packets (SYN = 1, ACK = 0) grouped by source IPv4 address reaching at least <b>{threshold} unique destination TCP ports</b> within a rolling <b>{window_sec}-second</b> window.', styles['body']))
        ip_summary: Dict[str, Dict[str, Any]] = {}
        for ev in events:
            src = _safe_text(ev.get('source_ip'), '-')
            if src == '-':
                continue
            entry = ip_summary.setdefault(src, {'source_ip': src, 'event_count': 0, 'max_ports': 0, 'first_seen': ev.get('timestamp', ''), 'last_seen': ev.get('timestamp', ''), 'latest_status': ev.get('firewall_status', '')})
            entry['event_count'] += 1
            entry['max_ports'] = max(entry['max_ports'], int(ev.get('unique_ports') or 0))
            if ev.get('timestamp'):
                entry['last_seen'] = ev['timestamp']
            entry['latest_status'] = ev.get('firewall_status', entry['latest_status'])
        if ip_summary:
            det_rows = [[Paragraph('Source IP', styles['table_header']), Paragraph('Recorded Events', styles['table_header']), Paragraph('Max Unique Ports', styles['table_header']), Paragraph('First Seen', styles['table_header']), Paragraph('Last Seen', styles['table_header']), Paragraph('Latest Status', styles['table_header'])]]
            for item in ip_summary.values():
                det_rows.append([Paragraph(_escape_xml(item['source_ip']), styles['table_cell']), Paragraph(str(item['event_count']), styles['table_cell']), Paragraph(str(item['max_ports']), styles['table_cell']), Paragraph(_escape_xml(_safe_text(item['first_seen'])), styles['table_cell']), Paragraph(_escape_xml(_safe_text(item['last_seen'])), styles['table_cell']), Paragraph(_escape_xml(_safe_text(item['latest_status'])), styles['table_cell'])])
            det_tbl = Table(det_rows, colWidths=[32 * mm, 24 * mm, 26 * mm, 33 * mm, 33 * mm, 26 * mm], repeatRows=1, splitByRow=1)
            det_tbl.setStyle(self._grid_table_style())
            story.append(det_tbl)
        else:
            story.append(Paragraph('No suspicious source IP detections were recorded during this investigation.', styles['muted']))
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph('3. Firewall Response', styles['section_h1']))
        story.append(Paragraph('Automated and manual Windows Defender Firewall actions associated with this investigation:', styles['body']))
        if rules:
            fw_rows = [[Paragraph('Rule Name', styles['table_header']), Paragraph('Source IP', styles['table_header']), Paragraph('Dir / Proto / Action', styles['table_header']), Paragraph('Status', styles['table_header']), Paragraph('Created At', styles['table_header']), Paragraph('Removed / Notes', styles['table_header'])]]
            for r in rules:
                notes = _safe_text(r.get('removed_at'), '') or _safe_text(r.get('failure_info'), '—')
                fw_rows.append([Paragraph(_escape_xml(_safe_text(r.get('rule_name'))), styles['table_cell']), Paragraph(_escape_xml(_safe_text(r.get('source_ip'))), styles['table_cell']), Paragraph(_escape_xml(f"{_safe_text(r.get('direction'))} / {_safe_text(r.get('protocol'))} / {_safe_text(r.get('action'))}"), styles['table_cell']), Paragraph(_escape_xml(_safe_text(r.get('status'))), styles['table_cell']), Paragraph(_escape_xml(_safe_text(r.get('created_at'))), styles['table_cell']), Paragraph(_escape_xml(notes), styles['table_cell'])])
            fw_tbl = Table(fw_rows, colWidths=[44 * mm, 26 * mm, 28 * mm, 20 * mm, 28 * mm, 28 * mm], repeatRows=1, splitByRow=1)
            fw_tbl.setStyle(self._grid_table_style())
            story.append(fw_tbl)
        else:
            story.append(Paragraph('No Windows Defender Firewall rules were created or modified during this investigation.', styles['muted']))
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph('4. Security Event Timeline', styles['section_h1']))
        if events:
            ev_rows = [[Paragraph('Event ID', styles['table_header_compact']), Paragraph('Timestamp', styles['table_header_compact']), Paragraph('Event Type', styles['table_header_compact']), Paragraph('Source IP', styles['table_header_compact']), Paragraph('Ports', styles['table_header_compact']), Paragraph('Port List', styles['table_header_compact']), Paragraph('FW', styles['table_header_compact']), Paragraph('Details', styles['table_header_compact'])]]
            for ev in events:
                ev_rows.append([Paragraph(f"EVT-{int(ev.get('event_id') or 0):06d}", styles['table_cell_compact']), Paragraph(_escape_xml(_safe_text(ev.get('timestamp'))), styles['table_cell_compact']), Paragraph(_escape_xml(_safe_text(ev.get('event_type'))), styles['table_cell_compact']), Paragraph(_escape_xml(_safe_text(ev.get('source_ip'))), styles['table_cell_compact']), Paragraph(str(int(ev.get('unique_ports') or 0)), styles['table_cell_compact']), Paragraph(_escape_xml(self._extract_ports(ev.get('detection_details'))), styles['table_cell_compact']), Paragraph(_escape_xml(_safe_text(ev.get('firewall_status'))), styles['table_cell_compact']), Paragraph(_escape_xml(_safe_text(ev.get('detection_details'), '—')), styles['table_cell_compact'])])
            ev_tbl = Table(ev_rows, colWidths=[22 * mm, 25 * mm, 25 * mm, 23 * mm, 14 * mm, 20 * mm, 22 * mm, 23 * mm], repeatRows=1, splitByRow=1)
            ev_tbl.setStyle(self._grid_table_style())
            story.append(ev_tbl)
        else:
            story.append(Paragraph('No chronological security events were recorded for this investigation.', styles['muted']))
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph('5. Technical Explanation', styles['section_h1']))
        story.append(Paragraph(f"{PROJECT_NAME} ({PRODUCT_NAME} {APP_VERSION}) captures live link-layer network traffic via Npcap and Scapy's AsyncSniffer using a BPF filter ('tcp'). Each IPv4/TCP packet is inspected for initial connection-initiation flags where the TCP SYN bit (0x02) is set and the TCP ACK bit (0x10) is unset. Destination TCP ports are tracked per source IP inside a thread-safe rolling window of {window_sec} seconds. When a single source IP contacts {threshold} or more unique destination TCP ports within that window, an automated containment task is queued to create an inbound TCP block rule in Windows Defender Firewall via PowerShell (New-NetFirewallRule), while preserving safety exclusions for loopback, multicast, unspecified, and configured host target addresses.", styles['body']))
        story.append(Paragraph('6. Detection Scope and Limitations', styles['section_h1']))
        story.append(Paragraph(_escape_xml(DETECTION_SCOPE_DISCLAIMER), styles['body']))
        story.append(Paragraph('Additional operational considerations: Windows Defender Firewall rules applied by PortShield block inbound TCP traffic from the identified source IP to this local Windows host only and require Windows Administrator privileges. Threshold matches indicate suspicious scanning patterns rather than confirmed malicious intent.', styles['muted']))
        return story

    @staticmethod
    def _grid_table_style() -> TableStyle:
        return TableStyle([('BACKGROUND', (0, 0), (-1, 0), NAVY_DARK), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white), ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, SLATE_LIGHT]), ('GRID', (0, 0), (-1, -1), 0.45, SLATE_BORDER), ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('TOPPADDING', (0, 0), (-1, -1), 5), ('BOTTOMPADDING', (0, 0), (-1, -1), 5), ('LEFTPADDING', (0, 0), (-1, -1), 5), ('RIGHTPADDING', (0, 0), (-1, -1), 5)])
