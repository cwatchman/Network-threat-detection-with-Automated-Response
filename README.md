# NetSentry | PortShield v1.0.0
**Network Threat Detection & Automated Response** — real-time TCP SYN port-scan detection and
automatic IP blocking (Windows Defender Firewall) for Windows networks.

This release is a **code-organisation-only** refactor: the former single-file `NetSentry.py` has been
split into exactly four modules. No behaviour, UI, database schema, detection rule or report
format was changed.

## Project structure
```
NetSentry_PortShield/
├── app.py            Streamlit entry point, SOC theme/CSS, session state, Investigate page,
│                     Dashboard (All Investigations + IP Block Management), Investigation Details,
│                     CSV / PDF download controls, bootstrap_application() and main()
├── database.py       Configuration constants, SQLite manager (WAL, FK), schema, legacy CSV
│                     migration, EventRepository, ScanRepository
├── detection.py      Admin check, Scapy/Npcap checks, interface discovery, TCP SYN filtering,
│                     PacketCaptureEngine (AsyncSniffer), PortScanDetector (15 ports / 10 s)
├── services.py       FirewallManager, FirewallWorker, MonitoringEngine, MonitoringService,
│                     HistoryService, ReportService (PDF), CSV exports
├── data/             SQLite database lives here (data/netsentry.db) — created automatically
├── reports/          Generated PDF reports
├── requirements.txt
└── README.md
```
Import graph (no cycles):  `app → services → detection → database`   (`app → database`, `services → database`)

## Run
1. Install **Npcap** (tick *WinPcap API-compatible mode*).
2. `pip install -r requirements.txt`
3. Open an **Administrator** terminal in this folder and run:
   ```
   streamlit run app.py
   ```
   Administrator rights are required for packet capture and Windows Defender Firewall rules.

## Keeping your existing data
Database and report paths are unchanged (`./data/netsentry.db`, `./reports/`, legacy
`./port_scan_events.csv`). To keep your history, **copy your existing `data/`, `reports/` (and
`port_scan_events.csv`, if present) into this folder** — or simply copy the four `.py` files over
your existing project folder. Nothing is reset or migrated destructively; the schema is created with
`CREATE TABLE IF NOT EXISTS` and the legacy-CSV import is idempotent.

## Detection scope
TCP SYN-based port-scan detection only (initial SYN, ACK=0). A source IP reaching 15 unique
destination TCP ports within a rolling 10-second window is queued for an inbound TCP block rule
named `PortScanDetector_Block_<ip>`. Only rules with that prefix are ever modified.
For authorized defensive monitoring only.
