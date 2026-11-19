"""NetSentry | PortShield - database.py
Configuration constants, SQLite connection management, schema, legacy CSV migration,
and the investigation / event / firewall-rule repositories.

This module is the base layer: it imports nothing from the other project modules.
"""
import csv
import hashlib
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, FrozenSet, Iterator, List, Optional, Tuple

PROJECT_NAME: str = 'NetSentry'

PRODUCT_NAME: str = 'PortShield'

MAIN_TITLE: str = 'Network Threat Detection & Automated Response'

SUBTITLE: str = 'Real-time port scan detection and automatic IP blocking for Windows networks.'

APP_VERSION: str = 'v1.0.0'

BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))

DATA_DIR: str = os.path.join(BASE_DIR, 'data')

REPORTS_DIR: str = os.path.join(BASE_DIR, 'reports')

DB_PATH: str = os.path.join(DATA_DIR, 'netsentry.db')

LEGACY_CSV_PATH: str = os.path.join(BASE_DIR, 'port_scan_events.csv')

WINDOW_SECONDS: int = 10

PORT_THRESHOLD: int = 15

CAPTURE_FILTER: str = 'tcp'

TCP_SYN_FLAG: int = 2

TCP_ACK_FLAG: int = 16

RULE_PREFIX: str = 'PortScanDetector_Block_'

FIREWALL_DIRECTION: str = 'Inbound'

FIREWALL_PROTOCOL: str = 'TCP'

FIREWALL_ACTION: str = 'Block'

FIREWALL_PROFILE: str = 'Any'

POWERSHELL_TIMEOUT_SECONDS: int = 20

PROTECTED_TARGET_IPS: FrozenSet[str] = frozenset({'172.31.32.1'})

AUTO_REFRESH_INTERVAL_MS: int = 4000

RECENT_EVENTS_LIMIT: int = 5

DEFAULT_PAGE_SIZE: int = 10

DETECTION_SCOPE_DISCLAIMER: str = 'Currently, the application focuses exclusively on TCP SYN-based port scan detection. Packet analysis and suspicious activity identification are limited to the implemented TCP SYN detection workflow. When the detection threshold is reached, the application creates a Windows Defender Firewall rule to block inbound TCP traffic from the identified source IP. Support for additional protocols and detection techniques is planned for upcoming versions.'

FOOTER_DISCLAIMER: str = 'For authorized defensive monitoring only. A detection threshold indicates suspicious behaviour, not confirmed malicious activity.'

@dataclass(frozen=True)
class AppConfig:
    """Immutable runtime configuration container."""
    project_name: str = PROJECT_NAME
    product_name: str = PRODUCT_NAME
    main_title: str = MAIN_TITLE
    subtitle: str = SUBTITLE
    version: str = APP_VERSION
    db_path: str = DB_PATH
    legacy_csv_path: str = LEGACY_CSV_PATH
    reports_dir: str = REPORTS_DIR
    window_seconds: int = WINDOW_SECONDS
    port_threshold: int = PORT_THRESHOLD
    capture_filter: str = CAPTURE_FILTER
    rule_prefix: str = RULE_PREFIX
    protected_target_ips: FrozenSet[str] = field(default_factory=lambda: PROTECTED_TARGET_IPS)

DEFAULT_CONFIG = AppConfig()

class DatabaseManager:
    """Manages short-lived, thread-safe SQLite connections with WAL and foreign keys."""

    def __init__(self, db_path: str=DB_PATH) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        parent = os.path.dirname(os.path.abspath(self.db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)

    def _create_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON;')
        conn.execute('PRAGMA journal_mode = WAL;')
        conn.execute('PRAGMA synchronous = NORMAL;')
        return conn

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Yields a transactional SQLite connection and closes it cleanly on exit."""
        with self._lock:
            conn = self._create_connection()
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

LEGACY_SCAN_ID = 'SCAN-LEGACY-CSV-0001'

SCHEMA_SQL = "\nCREATE TABLE IF NOT EXISTS investigations (\n    scan_id TEXT PRIMARY KEY,\n    start_time TEXT NOT NULL,\n    end_time TEXT,\n    status TEXT NOT NULL DEFAULT 'RUNNING',\n    network_interface TEXT,\n    detection_threshold INTEGER NOT NULL,\n    detection_window_seconds INTEGER NOT NULL,\n    total_events INTEGER NOT NULL DEFAULT 0,\n    unique_source_ips INTEGER NOT NULL DEFAULT 0,\n    successful_blocks INTEGER NOT NULL DEFAULT 0,\n    pending_blocks INTEGER NOT NULL DEFAULT 0,\n    failed_blocks INTEGER NOT NULL DEFAULT 0,\n    skipped_blocks INTEGER NOT NULL DEFAULT 0\n);\n\nCREATE TABLE IF NOT EXISTS security_events (\n    event_id INTEGER PRIMARY KEY AUTOINCREMENT,\n    scan_id TEXT NOT NULL,\n    timestamp TEXT NOT NULL,\n    source_ip TEXT NOT NULL,\n    event_type TEXT NOT NULL,\n    unique_ports INTEGER NOT NULL DEFAULT 0,\n    detection_details TEXT,\n    firewall_status TEXT NOT NULL DEFAULT 'INFORMATIONAL',\n    related_firewall_rule TEXT,\n    additional_info TEXT,\n    event_hash TEXT UNIQUE,\n    FOREIGN KEY (scan_id) REFERENCES investigations(scan_id) ON DELETE CASCADE\n);\n\nCREATE TABLE IF NOT EXISTS firewall_rules (\n    rule_id INTEGER PRIMARY KEY AUTOINCREMENT,\n    scan_id TEXT NOT NULL,\n    source_ip TEXT NOT NULL,\n    rule_name TEXT NOT NULL,\n    direction TEXT NOT NULL DEFAULT 'Inbound',\n    protocol TEXT NOT NULL DEFAULT 'TCP',\n    action TEXT NOT NULL DEFAULT 'Block',\n    created_at TEXT NOT NULL,\n    status TEXT NOT NULL DEFAULT 'ACTIVE',\n    removed_at TEXT,\n    failure_info TEXT,\n    related_event_id INTEGER,\n    FOREIGN KEY (scan_id) REFERENCES investigations(scan_id) ON DELETE CASCADE,\n    FOREIGN KEY (related_event_id) REFERENCES security_events(event_id) ON DELETE SET NULL\n);\n\nCREATE INDEX IF NOT EXISTS idx_events_scan_id ON security_events(scan_id);\nCREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);\nCREATE INDEX IF NOT EXISTS idx_events_source_ip ON security_events(source_ip);\nCREATE INDEX IF NOT EXISTS idx_events_event_type ON security_events(event_type);\nCREATE INDEX IF NOT EXISTS idx_events_fw_status ON security_events(firewall_status);\n\nCREATE INDEX IF NOT EXISTS idx_rules_scan_id ON firewall_rules(scan_id);\nCREATE INDEX IF NOT EXISTS idx_rules_source_ip ON firewall_rules(source_ip);\nCREATE INDEX IF NOT EXISTS idx_rules_status ON firewall_rules(status);\nCREATE INDEX IF NOT EXISTS idx_rules_rule_name ON firewall_rules(rule_name);\n"

def compute_event_hash(scan_id: str, timestamp: str, event_type: str, source_ip: str, unique_ports: int, details: str) -> str:
    payload = f'{scan_id}|{timestamp}|{event_type}|{source_ip}|{unique_ports}|{details}'.encode('utf-8')
    return hashlib.sha256(payload).hexdigest()

def map_event_to_firewall_status(event_type: str) -> str:
    upper = (event_type or '').upper()
    if upper == 'BLOCKED':
        return 'SUCCESSFUL'
    if 'PENDING' in upper:
        return 'PENDING'
    if 'FAILED' in upper or 'ERROR' in upper:
        return 'FAILED'
    if 'SKIPPED' in upper:
        return 'SKIPPED'
    if upper == 'UNBLOCKED':
        return 'UNBLOCKED'
    return 'INFORMATIONAL'

def build_rule_name(ip: str, prefix: str=RULE_PREFIX) -> str:
    sanitized = str(ip).strip().replace(':', '_').replace('.', '_')
    return f'{prefix}{sanitized}'

def initialize_database(db: DatabaseManager) -> None:
    """Create all tables and indexes if they do not already exist."""
    with db.connection() as conn:
        conn.executescript(SCHEMA_SQL)

def migrate_legacy_csv(db: DatabaseManager, csv_path: str=LEGACY_CSV_PATH, rule_prefix: str=RULE_PREFIX) -> Dict[str, int]:
    """
    Safely and idempotently migrate existing port_scan_events.csv rows into SQLite.
    Never overwrites existing records and avoids duplicates on repeated runs.
    """
    stats = {'processed': 0, 'inserted': 0, 'skipped': 0}
    if not csv_path or not os.path.exists(csv_path):
        return stats
    rows_to_import = []
    with open(csv_path, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            timestamp = (row.get('timestamp') or '').strip()
            event_type = (row.get('event') or '').strip()
            source_ip = (row.get('source_ip') or '').strip()
            details = (row.get('details') or '').strip()
            try:
                unique_ports = int(row.get('unique_ports') or 0)
            except ValueError:
                unique_ports = 0
            if not timestamp or not event_type:
                continue
            rows_to_import.append({'timestamp': timestamp, 'event_type': event_type, 'source_ip': source_ip or '-', 'unique_ports': unique_ports, 'details': details})
    if not rows_to_import:
        return stats
    timestamps = [r['timestamp'] for r in rows_to_import]
    earliest_ts = min(timestamps)
    latest_ts = max(timestamps)
    with db.connection() as conn:
        conn.execute('\n            INSERT OR IGNORE INTO investigations (\n                scan_id, start_time, end_time, status, network_interface,\n                detection_threshold, detection_window_seconds\n            ) VALUES (?, ?, ?, ?, ?, ?, ?)\n            ', (LEGACY_SCAN_ID, earliest_ts, latest_ts, 'IMPORTED', 'Legacy CSV Import', PORT_THRESHOLD, WINDOW_SECONDS))
        for item in rows_to_import:
            stats['processed'] += 1
            ev_hash = compute_event_hash(LEGACY_SCAN_ID, item['timestamp'], item['event_type'], item['source_ip'], item['unique_ports'], item['details'])
            fw_status = map_event_to_firewall_status(item['event_type'])
            rule_name: Optional[str] = None
            if item['source_ip'] not in ('', '-') and fw_status in ('SUCCESSFUL', 'PENDING', 'FAILED', 'SKIPPED', 'UNBLOCKED'):
                rule_name = build_rule_name(item['source_ip'], rule_prefix)
            cur = conn.execute('\n                INSERT OR IGNORE INTO security_events (\n                    scan_id, timestamp, source_ip, event_type, unique_ports,\n                    detection_details, firewall_status, related_firewall_rule,\n                    additional_info, event_hash\n                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n                ', (LEGACY_SCAN_ID, item['timestamp'], item['source_ip'], item['event_type'], item['unique_ports'], item['details'], fw_status, rule_name, 'Migrated from legacy port_scan_events.csv', ev_hash))
            if cur.rowcount == 0:
                stats['skipped'] += 1
                continue
            stats['inserted'] += 1
            event_id = cur.lastrowid
            if item['event_type'].upper() == 'BLOCKED' and rule_name:
                existing_rule = conn.execute('\n                    SELECT rule_id FROM firewall_rules\n                    WHERE scan_id = ? AND rule_name = ? AND created_at = ?\n                    ', (LEGACY_SCAN_ID, rule_name, item['timestamp'])).fetchone()
                if not existing_rule:
                    conn.execute('\n                        INSERT INTO firewall_rules (\n                            scan_id, source_ip, rule_name, direction, protocol,\n                            action, created_at, status, related_event_id\n                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)\n                        ', (LEGACY_SCAN_ID, item['source_ip'], rule_name, FIREWALL_DIRECTION, FIREWALL_PROTOCOL, FIREWALL_ACTION, item['timestamp'], 'ACTIVE', event_id))
            elif item['event_type'].upper() == 'UNBLOCKED' and rule_name:
                conn.execute("\n                    UPDATE firewall_rules\n                    SET status = 'REMOVED', removed_at = ?\n                    WHERE rule_name = ? AND status = 'ACTIVE'\n                    ", (item['timestamp'], rule_name))
        _refresh_investigation_counters(conn, LEGACY_SCAN_ID)
    return stats

def _refresh_investigation_counters(conn: sqlite3.Connection, scan_id: str) -> None:
    """Recalculate investigation aggregate columns accurately from security_events."""
    row = conn.execute("\n        SELECT\n            COUNT(*) AS total_events,\n            COUNT(DISTINCT CASE WHEN source_ip != '-' AND source_ip != '' THEN source_ip END) AS unique_ips,\n            SUM(CASE WHEN event_type = 'BLOCKED' AND firewall_status = 'SUCCESSFUL' THEN 1 ELSE 0 END) AS successful_blocks,\n            SUM(CASE WHEN event_type = 'DETECTED - BLOCK PENDING' AND firewall_status = 'PENDING' THEN 1 ELSE 0 END) AS pending_blocks,\n            SUM(CASE WHEN event_type = 'BLOCK FAILED' AND firewall_status = 'FAILED' THEN 1 ELSE 0 END) AS failed_blocks,\n            SUM(CASE WHEN event_type = 'BLOCK SKIPPED' AND firewall_status = 'SKIPPED' THEN 1 ELSE 0 END) AS skipped_blocks\n        FROM security_events\n        WHERE scan_id = ?\n        ", (scan_id,)).fetchone()
    if row:
        conn.execute('\n            UPDATE investigations\n            SET total_events = ?,\n                unique_source_ips = ?,\n                successful_blocks = ?,\n                pending_blocks = ?,\n                failed_blocks = ?,\n                skipped_blocks = ?\n            WHERE scan_id = ?\n            ', (int(row['total_events'] or 0), int(row['unique_ips'] or 0), int(row['successful_blocks'] or 0), int(row['pending_blocks'] or 0), int(row['failed_blocks'] or 0), int(row['skipped_blocks'] or 0), scan_id))

class EventRepository:
    """Data access layer for security_events and firewall_rules tables."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def record_event(self, scan_id: str, event_type: str, source_ip: str, unique_ports: int, detection_details: str, firewall_status: Optional[str]=None, related_firewall_rule: Optional[str]=None, additional_info: Optional[str]=None, timestamp: Optional[str]=None, deduplicate: bool=False) -> int:
        ts = timestamp or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        fw_status = firewall_status or map_event_to_firewall_status(event_type)
        ev_hash = compute_event_hash(scan_id, ts, event_type, source_ip, unique_ports, detection_details) if deduplicate else None
        with self.db.connection() as conn:
            if fw_status in ('SUCCESSFUL', 'FAILED', 'SKIPPED'):
                conn.execute("\n                    UPDATE security_events\n                    SET firewall_status = ?\n                    WHERE scan_id = ? AND source_ip = ? AND firewall_status = 'PENDING'\n                    ", (fw_status, scan_id, source_ip))
            cur = conn.execute('\n                INSERT OR IGNORE INTO security_events (\n                    scan_id, timestamp, source_ip, event_type, unique_ports,\n                    detection_details, firewall_status, related_firewall_rule,\n                    additional_info, event_hash\n                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n                ', (scan_id, ts, source_ip, event_type, int(unique_ports), detection_details, fw_status, related_firewall_rule, additional_info, ev_hash))
            event_id = int(cur.lastrowid or 0)
            _refresh_investigation_counters(conn, scan_id)
        return event_id

    def record_firewall_rule(self, scan_id: str, source_ip: str, rule_name: str, status: str='ACTIVE', direction: str=FIREWALL_DIRECTION, protocol: str=FIREWALL_PROTOCOL, action: str=FIREWALL_ACTION, created_at: Optional[str]=None, failure_info: Optional[str]=None, related_event_id: Optional[int]=None) -> int:
        ts = created_at or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with self.db.connection() as conn:
            if status == 'ACTIVE':
                conn.execute("\n                    UPDATE firewall_rules\n                    SET status = 'SUPERSEDED', removed_at = ?\n                    WHERE rule_name = ? AND status = 'ACTIVE'\n                    ", (ts, rule_name))
            cur = conn.execute('\n                INSERT INTO firewall_rules (\n                    scan_id, source_ip, rule_name, direction, protocol,\n                    action, created_at, status, failure_info, related_event_id\n                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n                ', (scan_id, source_ip, rule_name, direction, protocol, action, ts, status, failure_info, related_event_id))
            return int(cur.lastrowid or 0)

    def mark_firewall_rule_removed(self, rule_name: str, removed_at: Optional[str]=None) -> int:
        ts = removed_at or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with self.db.connection() as conn:
            cur = conn.execute("\n                UPDATE firewall_rules\n                SET status = 'REMOVED', removed_at = ?\n                WHERE rule_name = ? AND status = 'ACTIVE'\n                ", (ts, rule_name))
            return cur.rowcount

    def get_recent_events(self, scan_id: Optional[str]=None, limit: int=5) -> List[Dict[str, Any]]:
        with self.db.connection() as conn:
            if scan_id:
                rows = conn.execute('\n                    SELECT * FROM security_events\n                    WHERE scan_id = ?\n                    ORDER BY event_id DESC\n                    LIMIT ?\n                    ', (scan_id, limit)).fetchall()
            else:
                rows = conn.execute('\n                    SELECT * FROM security_events\n                    ORDER BY event_id DESC\n                    LIMIT ?\n                    ', (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_all_events(self, limit: int=5000) -> List[Dict[str, Any]]:
        """Return the complete recent-to-oldest event ledger for dashboard reporting."""
        with self.db.connection() as conn:
            rows = conn.execute('SELECT * FROM security_events ORDER BY timestamp DESC, event_id DESC LIMIT ?', (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_events_for_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute('\n                SELECT * FROM security_events\n                WHERE scan_id = ?\n                ORDER BY timestamp ASC, event_id ASC\n                ', (scan_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_rules_for_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute('\n                SELECT fr.*, se.event_type AS related_event_type,\n                       se.timestamp AS related_event_timestamp,\n                       se.unique_ports AS related_unique_ports,\n                       se.detection_details AS related_detection_details\n                FROM firewall_rules fr\n                LEFT JOIN security_events se ON fr.related_event_id = se.event_id\n                WHERE fr.scan_id = ?\n                ORDER BY fr.rule_id DESC\n                ', (scan_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_all_managed_rules(self, limit: int=200) -> List[Dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute('\n                SELECT fr.*, se.event_type AS related_event_type,\n                       se.timestamp AS related_event_timestamp,\n                       se.unique_ports AS related_unique_ports,\n                       se.detection_details AS related_detection_details\n                FROM firewall_rules fr\n                LEFT JOIN security_events se ON fr.related_event_id = se.event_id\n                ORDER BY fr.rule_id DESC\n                LIMIT ?\n                ', (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_active_blocked_rules(self) -> List[Dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute("\n                SELECT * FROM firewall_rules\n                WHERE status = 'ACTIVE'\n                ORDER BY created_at DESC, rule_id DESC\n                ").fetchall()
        return [dict(r) for r in rows]

    def get_rule_by_id(self, rule_id: int) -> Optional[Dict[str, Any]]:
        with self.db.connection() as conn:
            row = conn.execute('\n                SELECT fr.*, se.event_type AS related_event_type,\n                       se.timestamp AS related_event_timestamp,\n                       se.unique_ports AS related_unique_ports,\n                       se.detection_details AS related_detection_details\n                FROM firewall_rules fr\n                LEFT JOIN security_events se ON fr.related_event_id = se.event_id\n                WHERE fr.rule_id = ?\n                ', (rule_id,)).fetchone()
        return dict(row) if row else None

    def query_history(self, scan_id_query: str='', source_ip_query: str='', start_date: Optional[str]=None, end_date: Optional[str]=None, event_type: str='ALL', firewall_status: str='ALL', sort_order: str='NEWEST', page: int=1, page_size: int=10) -> Tuple[List[Dict[str, Any]], int]:
        """
        Query investigation-level history records joined with event summaries,
        supporting search, filtering, sorting, and pagination.
        """
        where_clauses: List[str] = []
        params: List[Any] = []
        if scan_id_query.strip():
            where_clauses.append('i.scan_id LIKE ?')
            params.append(f'%{scan_id_query.strip()}%')
        if source_ip_query.strip():
            where_clauses.append('\n                EXISTS (\n                    SELECT 1 FROM security_events se_ip\n                    WHERE se_ip.scan_id = i.scan_id AND se_ip.source_ip LIKE ?\n                )\n                ')
            params.append(f'%{source_ip_query.strip()}%')
        if start_date:
            where_clauses.append('substr(i.start_time, 1, 10) >= ?')
            params.append(start_date)
        if end_date:
            where_clauses.append('substr(i.start_time, 1, 10) <= ?')
            params.append(end_date)
        if event_type and event_type != 'ALL':
            where_clauses.append('\n                EXISTS (\n                    SELECT 1 FROM security_events se_et\n                    WHERE se_et.scan_id = i.scan_id AND se_et.event_type = ?\n                )\n                ')
            params.append(event_type)
        if firewall_status and firewall_status != 'ALL':
            where_clauses.append('\n                EXISTS (\n                    SELECT 1 FROM security_events se_fw\n                    WHERE se_fw.scan_id = i.scan_id AND se_fw.firewall_status = ?\n                )\n                ')
            params.append(firewall_status)
        where_sql = 'WHERE ' + ' AND '.join(where_clauses) if where_clauses else ''
        order_sql = 'ASC' if sort_order.upper() == 'OLDEST' else 'DESC'
        count_sql = f'SELECT COUNT(*) AS cnt FROM investigations i {where_sql}'
        offset = max(0, (max(1, page) - 1) * page_size)
        data_sql = f"\n            SELECT\n                i.scan_id,\n                i.start_time AS timestamp,\n                i.end_time,\n                i.status AS investigation_status,\n                i.network_interface,\n                i.detection_threshold,\n                i.detection_window_seconds,\n                i.total_events AS event_count,\n                i.unique_source_ips,\n                i.successful_blocks,\n                i.pending_blocks,\n                i.failed_blocks,\n                i.skipped_blocks,\n                COALESCE(\n                    (\n                        SELECT GROUP_CONCAT(DISTINCT se.source_ip)\n                        FROM security_events se\n                        WHERE se.scan_id = i.scan_id AND se.source_ip != '-'\n                    ),\n                    '-'\n                ) AS source_ips,\n                COALESCE(\n                    (\n                        SELECT MAX(se.unique_ports)\n                        FROM security_events se\n                        WHERE se.scan_id = i.scan_id\n                    ),\n                    0\n                ) AS max_unique_ports,\n                COALESCE(\n                    (\n                        SELECT GROUP_CONCAT('EVT-' || printf('%06d', se.event_id), ', ')\n                        FROM security_events se\n                        WHERE se.scan_id = i.scan_id\n                    ),\n                    '—'\n                ) AS event_ids,\n                COALESCE(\n                    (\n                        SELECT se.firewall_status\n                        FROM security_events se\n                        WHERE se.scan_id = i.scan_id\n                        ORDER BY se.event_id DESC\n                        LIMIT 1\n                    ),\n                    'NO EVENTS'\n                ) AS latest_firewall_status,\n                COALESCE(\n                    (\n                        SELECT se.detection_details\n                        FROM security_events se\n                        WHERE se.scan_id = i.scan_id\n                        ORDER BY se.event_id DESC\n                        LIMIT 1\n                    ),\n                    'Monitoring session recorded'\n                ) AS latest_details\n            FROM investigations i\n            {where_sql}\n            ORDER BY i.start_time {order_sql}, i.scan_id {order_sql}\n            LIMIT ? OFFSET ?\n        "
        with self.db.connection() as conn:
            total_count = int(conn.execute(count_sql, params).fetchone()['cnt'])
            rows = conn.execute(data_sql, [*params, page_size, offset]).fetchall()
        return ([dict(r) for r in rows], total_count)

    def get_dashboard_analytics(self) -> Dict[str, Any]:
        """Retrieve real SQLite analytics datasets for Dashboard visualizations."""
        with self.db.connection() as conn:
            trend_rows = conn.execute("\n                SELECT substr(timestamp, 1, 13) || ':00' AS time_bucket,\n                       COUNT(*) AS event_count\n                FROM security_events\n                GROUP BY time_bucket\n                ORDER BY time_bucket ASC\n                LIMIT 48\n                ").fetchall()
            fw_dist_rows = conn.execute("\n                SELECT firewall_status, COUNT(*) AS count\n                FROM security_events\n                WHERE\n                    (event_type = 'DETECTED - BLOCK PENDING' AND firewall_status = 'PENDING')\n                    OR (event_type = 'BLOCKED' AND firewall_status = 'SUCCESSFUL')\n                    OR (event_type = 'BLOCK FAILED' AND firewall_status = 'FAILED')\n                    OR (event_type = 'BLOCK SKIPPED' AND firewall_status = 'SKIPPED')\n                    OR firewall_status NOT IN ('PENDING', 'SUCCESSFUL', 'FAILED', 'SKIPPED')\n                GROUP BY firewall_status\n                ORDER BY count DESC\n                ").fetchall()
            top_ip_rows = conn.execute("\n                SELECT source_ip,\n                       COUNT(*) AS event_count,\n                       MAX(unique_ports) AS max_ports\n                FROM security_events\n                WHERE source_ip != '-' AND source_ip != ''\n                GROUP BY source_ip\n                ORDER BY event_count DESC, max_ports DESC\n                LIMIT 10\n                ").fetchall()
            timeline_rows = conn.execute('\n                SELECT event_id, scan_id, timestamp, source_ip, event_type,\n                       unique_ports, firewall_status, detection_details\n                FROM security_events\n                ORDER BY timestamp DESC, event_id DESC\n                LIMIT 30\n                ').fetchall()
        return {'activity_trend': [dict(r) for r in trend_rows], 'firewall_distribution': [dict(r) for r in fw_dist_rows], 'top_source_ips': [dict(r) for r in top_ip_rows], 'detection_timeline': [dict(r) for r in timeline_rows]}

def generate_scan_id(now: Optional[datetime]=None) -> str:
    """Generate a guaranteed-unique Scan ID with timestamp + random hex suffix."""
    dt = now or datetime.now()
    suffix = uuid.uuid4().hex[:6].upper()
    return f"SCAN-{dt.strftime('%Y%m%d-%H%M%S')}-{suffix}"

class ScanRepository:
    """Data access layer for investigations and aggregate SOC statistics."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def create_investigation(self, network_interface: str, threshold: int=PORT_THRESHOLD, window_seconds: int=WINDOW_SECONDS, scan_id: Optional[str]=None, start_time: Optional[str]=None) -> Dict[str, Any]:
        sid = scan_id or generate_scan_id()
        started = start_time or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with self.db.connection() as conn:
            conn.execute("\n                INSERT INTO investigations (\n                    scan_id, start_time, status, network_interface,\n                    detection_threshold, detection_window_seconds\n                ) VALUES (?, ?, 'RUNNING', ?, ?, ?)\n                ", (sid, started, network_interface, threshold, window_seconds))
            row = conn.execute('SELECT * FROM investigations WHERE scan_id = ?', (sid,)).fetchone()
        return dict(row)

    def complete_investigation(self, scan_id: str, status: str='COMPLETED', end_time: Optional[str]=None) -> Optional[Dict[str, Any]]:
        ended = end_time or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with self.db.connection() as conn:
            _refresh_investigation_counters(conn, scan_id)
            conn.execute('\n                UPDATE investigations\n                SET end_time = ?, status = ?\n                WHERE scan_id = ?\n                ', (ended, status, scan_id))
            row = conn.execute('SELECT * FROM investigations WHERE scan_id = ?', (scan_id,)).fetchone()
        return dict(row) if row else None

    def close_stale_running_investigations(self) -> int:
        """Mark any leftover RUNNING investigations from an unexpected crash as INTERRUPTED."""
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with self.db.connection() as conn:
            stale = conn.execute("SELECT scan_id FROM investigations WHERE status = 'RUNNING'").fetchall()
            for r in stale:
                _refresh_investigation_counters(conn, r['scan_id'])
            cur = conn.execute("\n                UPDATE investigations\n                SET status = 'INTERRUPTED', end_time = COALESCE(end_time, ?)\n                WHERE status = 'RUNNING'\n                ", (now_str,))
            return cur.rowcount

    def refresh_counters(self, scan_id: str) -> None:
        with self.db.connection() as conn:
            _refresh_investigation_counters(conn, scan_id)

    def get_investigation(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self.db.connection() as conn:
            _refresh_investigation_counters(conn, scan_id)
            row = conn.execute('SELECT * FROM investigations WHERE scan_id = ?', (scan_id,)).fetchone()
        return dict(row) if row else None

    def list_investigations(self, limit: int=200) -> List[Dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute('\n                SELECT * FROM investigations\n                ORDER BY start_time DESC, scan_id DESC\n                LIMIT ?\n                ', (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_session_overview(self, scan_id: Optional[str]) -> Dict[str, int]:
        """Return accurate KPI counters for a single investigation session."""
        if not scan_id:
            return {'total_events': 0, 'unique_source_ips': 0, 'successful_blocks': 0, 'pending_blocks': 0, 'failed_blocks': 0, 'skipped_blocks': 0}
        with self.db.connection() as conn:
            row = conn.execute("\n                SELECT\n                    COUNT(*) AS total_events,\n                    COUNT(DISTINCT CASE WHEN source_ip != '-' AND source_ip != '' THEN source_ip END) AS unique_ips,\n                    SUM(CASE WHEN event_type = 'BLOCKED' AND firewall_status = 'SUCCESSFUL' THEN 1 ELSE 0 END) AS successful_blocks,\n                    SUM(CASE WHEN event_type = 'DETECTED - BLOCK PENDING' AND firewall_status = 'PENDING' THEN 1 ELSE 0 END) AS pending_blocks,\n                    SUM(CASE WHEN event_type = 'BLOCK FAILED' AND firewall_status = 'FAILED' THEN 1 ELSE 0 END) AS failed_blocks,\n                    SUM(CASE WHEN event_type = 'BLOCK SKIPPED' AND firewall_status = 'SKIPPED' THEN 1 ELSE 0 END) AS skipped_blocks\n                FROM security_events\n                WHERE scan_id = ?\n                ", (scan_id,)).fetchone()
        return {'total_events': int(row['total_events'] or 0), 'unique_source_ips': int(row['unique_ips'] or 0), 'successful_blocks': int(row['successful_blocks'] or 0), 'pending_blocks': int(row['pending_blocks'] or 0), 'failed_blocks': int(row['failed_blocks'] or 0), 'skipped_blocks': int(row['skipped_blocks'] or 0)}

    def get_all_time_metrics(self) -> Dict[str, Any]:
        """
        Compute accurate all-time SOC metrics directly from SQLite without double-counting.
        """
        with self.db.connection() as conn:
            inv_row = conn.execute('SELECT COUNT(*) AS total_investigations FROM investigations').fetchone()
            ev_row = conn.execute("\n                SELECT\n                    COUNT(*) AS total_events,\n                    COUNT(DISTINCT CASE WHEN source_ip != '-' AND source_ip != '' THEN source_ip END) AS unique_source_ips,\n                    SUM(CASE WHEN event_type = 'BLOCKED' AND firewall_status = 'SUCCESSFUL' THEN 1 ELSE 0 END) AS successful_blocks,\n                    SUM(CASE WHEN event_type = 'DETECTED - BLOCK PENDING' AND firewall_status = 'PENDING' THEN 1 ELSE 0 END) AS pending_blocks,\n                    SUM(CASE WHEN event_type = 'BLOCK FAILED' AND firewall_status = 'FAILED' THEN 1 ELSE 0 END) AS block_failures,\n                    SUM(CASE WHEN event_type = 'BLOCK SKIPPED' AND firewall_status = 'SKIPPED' THEN 1 ELSE 0 END) AS skipped_blocks,\n                    MAX(timestamp) AS last_activity\n                FROM security_events\n                ").fetchone()
            active_rules_row = conn.execute("SELECT COUNT(DISTINCT source_ip) AS active_blocked_ips FROM firewall_rules WHERE status = 'ACTIVE'").fetchone()
        return {'total_investigations': int(inv_row['total_investigations'] or 0), 'total_events': int(ev_row['total_events'] or 0), 'unique_source_ips': int(ev_row['unique_source_ips'] or 0), 'successful_blocks': int(ev_row['successful_blocks'] or 0), 'pending_blocks': int(ev_row['pending_blocks'] or 0), 'block_failures': int(ev_row['block_failures'] or 0), 'skipped_blocks': int(ev_row['skipped_blocks'] or 0), 'active_blocked_ips': int(active_rules_row['active_blocked_ips'] or 0), 'last_activity': ev_row['last_activity'] or 'No activity recorded'}
