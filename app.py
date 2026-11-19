"""NetSentry | PortShield - app.py
Streamlit entry point: page configuration, SOC theme / CSS, session-state management,
and the Investigate, Dashboard (All Investigations + IP Block Management) and
Investigation Details UI, plus report / CSV download controls.

Run with:  streamlit run app.py
"""
import atexit
import csv
import html
import io
import math
import re
from datetime import datetime
from typing import Any, Dict, List

import pandas as pd
import streamlit as st

from database import (
    APP_VERSION,
    AUTO_REFRESH_INTERVAL_MS,
    DB_PATH,
    DETECTION_SCOPE_DISCLAIMER,
    FOOTER_DISCLAIMER,
    LEGACY_CSV_PATH,
    MAIN_TITLE,
    PRODUCT_NAME,
    PROJECT_NAME,
    DatabaseManager,
    EventRepository,
    ScanRepository,
    initialize_database,
    migrate_legacy_csv,
)
from services import (
    FirewallManager,
    HistoryService,
    MonitoringEngine,
    MonitoringService,
    ReportService,
)

SVG_3D_SHIELD_LOGO = '\n<svg width="46" height="46" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="NetSentry PortShield 3D Logo">\n  <defs>\n    <linearGradient id="shieldExtrude" x1="10" y1="6" x2="56" y2="58" gradientUnits="userSpaceOnUse">\n      <stop offset="0%" stop-color="#0ea5e9"/>\n      <stop offset="100%" stop-color="#1e3a8a"/>\n    </linearGradient>\n    <linearGradient id="shieldLeft" x1="12" y1="8" x2="32" y2="56" gradientUnits="userSpaceOnUse">\n      <stop offset="0%" stop-color="#3b82f6"/>\n      <stop offset="100%" stop-color="#1d4ed8"/>\n    </linearGradient>\n    <linearGradient id="shieldRight" x1="32" y1="8" x2="54" y2="54" gradientUnits="userSpaceOnUse">\n      <stop offset="0%" stop-color="#22d3ee"/>\n      <stop offset="100%" stop-color="#0284c7"/>\n    </linearGradient>\n    <linearGradient id="shieldCore" x1="18" y1="14" x2="46" y2="50" gradientUnits="userSpaceOnUse">\n      <stop offset="0%" stop-color="#0f172a"/>\n      <stop offset="100%" stop-color="#060b19"/>\n    </linearGradient>\n    <filter id="shieldGlow" x="-20%" y="-20%" width="140%" height="140%">\n      <feDropShadow dx="0" dy="4" stdDeviation="4" flood-color="#06b6d4" flood-opacity="0.35"/>\n    </filter>\n  </defs>\n  <g filter="url(#shieldGlow)">\n    <!-- 3D Back Extrusion -->\n    <path d="M34 6L56 15V31C56 45.5 46.6 56.8 34 61C21.4 56.8 12 45.5 12 31V15L34 6Z" fill="url(#shieldExtrude)"/>\n    <!-- Left 3D Facet -->\n    <path d="M31 4L10 13V29.5C10 43.8 19.1 55 31 59V4Z" fill="url(#shieldLeft)"/>\n    <!-- Right 3D Facet -->\n    <path d="M31 4L52 13V29.5C52 43.8 42.9 55 31 59V4Z" fill="url(#shieldRight)"/>\n    <!-- Inner Recessed Armor Plate -->\n    <path d="M31 11L16 17.5V29.5C16 40.2 22.4 48.6 31 52C39.6 48.6 46 40.2 46 29.5V17.5L31 11Z" fill="url(#shieldCore)" stroke="#38bdf8" stroke-width="1.2"/>\n    <!-- Specular Pulse Check -->\n    <path d="M23 31.5L28.5 37L40 24.5" stroke="#22d3ee" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/>\n    <path d="M23 31.5L28.5 37L40 24.5" stroke="#ffffff" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>\n  </g>\n</svg>\n'

SVG_3D_NETWORK_NODE = '\n<svg width="36" height="36" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">\n  <defs>\n    <linearGradient id="cubeTop" x1="16" y1="10" x2="48" y2="28" gradientUnits="userSpaceOnUse">\n      <stop offset="0%" stop-color="#38bdf8"/>\n      <stop offset="100%" stop-color="#2563eb"/>\n    </linearGradient>\n    <linearGradient id="cubeLeft" x1="14" y1="22" x2="32" y2="52" gradientUnits="userSpaceOnUse">\n      <stop offset="0%" stop-color="#1d4ed8"/>\n      <stop offset="100%" stop-color="#0f172a"/>\n    </linearGradient>\n    <linearGradient id="cubeRight" x1="32" y1="22" x2="50" y2="52" gradientUnits="userSpaceOnUse">\n      <stop offset="0%" stop-color="#06b6d4"/>\n      <stop offset="100%" stop-color="#0e7490"/>\n    </linearGradient>\n  </defs>\n  <polygon points="32,10 50,20 32,30 14,20" fill="url(#cubeTop)"/>\n  <polygon points="14,20 32,30 32,52 14,42" fill="url(#cubeLeft)"/>\n  <polygon points="50,20 32,30 32,52 50,42" fill="url(#cubeRight)"/>\n  <circle cx="32" cy="10" r="3.5" fill="#e0f2fe"/>\n  <circle cx="14" cy="42" r="3" fill="#38bdf8"/>\n  <circle cx="50" cy="42" r="3" fill="#22d3ee"/>\n</svg>\n'

SVG_3D_RADAR_SCAN = '\n<svg width="36" height="36" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">\n  <defs>\n    <radialGradient id="radarSphere" cx="35%" cy="30%" r="70%">\n      <stop offset="0%" stop-color="#67e8f9"/>\n      <stop offset="45%" stop-color="#2563eb"/>\n      <stop offset="100%" stop-color="#091226"/>\n    </radialGradient>\n    <linearGradient id="radarSweep" x1="32" y1="32" x2="52" y2="16" gradientUnits="userSpaceOnUse">\n      <stop offset="0%" stop-color="#22d3ee" stop-opacity="0.1"/>\n      <stop offset="100%" stop-color="#22d3ee" stop-opacity="0.85"/>\n    </linearGradient>\n  </defs>\n  <ellipse cx="32" cy="54" rx="18" ry="4" fill="#020617" opacity="0.75"/>\n  <circle cx="32" cy="30" r="21" fill="url(#radarSphere)" stroke="#38bdf8" stroke-width="1.4"/>\n  <ellipse cx="32" cy="30" rx="14" ry="21" stroke="#7dd3fc" stroke-opacity="0.35" stroke-width="1"/>\n  <ellipse cx="32" cy="30" rx="21" ry="9" stroke="#7dd3fc" stroke-opacity="0.35" stroke-width="1"/>\n  <path d="M32 30L48 16A21 21 0 0 1 52 33Z" fill="url(#radarSweep)"/>\n  <circle cx="42" cy="22" r="3" fill="#ffffff"/>\n</svg>\n'

SVG_3D_FIREWALL_WALL = '\n<svg width="36" height="36" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">\n  <defs>\n    <linearGradient id="wallFace" x1="10" y1="14" x2="48" y2="52" gradientUnits="userSpaceOnUse">\n      <stop offset="0%" stop-color="#2563eb"/>\n      <stop offset="100%" stop-color="#0f172a"/>\n    </linearGradient>\n    <linearGradient id="wallSide" x1="46" y1="14" x2="56" y2="48" gradientUnits="userSpaceOnUse">\n      <stop offset="0%" stop-color="#06b6d4"/>\n      <stop offset="100%" stop-color="#155e75"/>\n    </linearGradient>\n  </defs>\n  <polygon points="12,18 46,12 46,48 12,54" fill="url(#wallFace)" stroke="#38bdf8" stroke-width="1.2"/>\n  <polygon points="46,12 54,16 54,50 46,48" fill="url(#wallSide)"/>\n  <line x1="12" y1="30" x2="46" y2="24" stroke="#38bdf8" stroke-opacity="0.55" stroke-width="1.3"/>\n  <line x1="12" y1="42" x2="46" y2="36" stroke="#38bdf8" stroke-opacity="0.55" stroke-width="1.3"/>\n  <line x1="29" y1="15" x2="29" y2="27" stroke="#38bdf8" stroke-opacity="0.55" stroke-width="1.3"/>\n  <line x1="21" y1="28.5" x2="21" y2="40.5" stroke="#38bdf8" stroke-opacity="0.55" stroke-width="1.3"/>\n  <line x1="37" y1="25.5" x2="37" y2="37.5" stroke="#38bdf8" stroke-opacity="0.55" stroke-width="1.3"/>\n</svg>\n'

SVG_3D_PACKET_STREAM = '\n<svg width="36" height="36" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">\n  <defs>\n    <linearGradient id="pktA" x1="8" y1="14" x2="36" y2="38" gradientUnits="userSpaceOnUse">\n      <stop offset="0%" stop-color="#22d3ee"/>\n      <stop offset="100%" stop-color="#1d4ed8"/>\n    </linearGradient>\n    <linearGradient id="pktB" x1="26" y1="24" x2="56" y2="50" gradientUnits="userSpaceOnUse">\n      <stop offset="0%" stop-color="#3b82f6"/>\n      <stop offset="100%" stop-color="#0f172a"/>\n    </linearGradient>\n  </defs>\n  <polygon points="22,12 36,20 22,28 8,20" fill="#67e8f9"/>\n  <polygon points="8,20 22,28 22,42 8,34" fill="url(#pktA)"/>\n  <polygon points="36,20 22,28 22,42 36,34" fill="#1e40af"/>\n  <polygon points="42,24 56,32 42,40 28,32" fill="#38bdf8"/>\n  <polygon points="28,32 42,40 42,54 28,46" fill="url(#pktB)"/>\n  <polygon points="56,32 42,40 42,54 56,46" fill="#0284c7"/>\n</svg>\n'

def inject_soc_theme() -> None:
    """Inject the dark SOC stylesheet into Streamlit."""
    st.markdown('\n        <style>\n        @import url(\'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap\');\n\n        :root {\n            --bg-main: #060b19;\n            --bg-secondary: #0d1526;\n            --bg-card: #101b33;\n            --bg-card-hover: #142240;\n            --border-subtle: rgba(56, 189, 248, 0.22);\n            --border-strong: rgba(34, 211, 238, 0.55);\n            --accent-blue: #2563eb;\n            --accent-blue-light: #3b82f6;\n            --accent-cyan: #06b6d4;\n            --accent-cyan-bright: #22d3ee;\n            --status-green: #10b981;\n            --status-amber: #f59e0b;\n            --status-red: #ef4444;\n            --text-primary: #f8fafc;\n            --text-muted: #94a3b8;\n        }\n\n        /* Hide default Streamlit chrome & sidebar */\n        #MainMenu, footer, header[data-testid="stHeader"] {\n            visibility: hidden;\n            height: 0px;\n        }\n        section[data-testid="stSidebar"] {\n            display: none !important;\n        }\n\n        html, body, [data-testid="stAppViewContainer"], .stApp {\n            background-color: var(--bg-main) !important;\n            color: var(--text-primary) !important;\n            font-family: \'Inter\', -apple-system, BlinkMacSystemFont, sans-serif !important;\n        }\n\n        .block-container {\n            padding-top: 1.1rem !important;\n            padding-bottom: 2.2rem !important;\n            max-width: 1380px !important;\n        }\n\n        h1, h2, h3, h4 {\n            color: var(--text-primary) !important;\n            font-family: \'Inter\', sans-serif !important;\n            letter-spacing: -0.015em;\n        }\n\n        p, label, span, div {\n            color: var(--text-primary);\n        }\n\n        /* Common Header Bar */\n        .ns-header {\n            background: linear-gradient(135deg, #0b1329 0%, #101d3b 55%, #0b162e 100%);\n            border: 1px solid var(--border-subtle);\n            border-radius: 14px;\n            padding: 14px 22px;\n            margin-bottom: 18px;\n            display: flex;\n            align-items: center;\n            justify-content: space-between;\n            box-shadow: 0 10px 28px rgba(2, 6, 23, 0.65);\n        }\n        .ns-header-left {\n            display: flex;\n            align-items: center;\n            gap: 14px;\n        }\n        .ns-brand-title {\n            font-size: 1.38rem;\n            font-weight: 800;\n            color: #ffffff;\n            line-height: 1.15;\n            display: flex;\n            align-items: center;\n            gap: 10px;\n        }\n        .ns-version-badge {\n            background: rgba(6, 182, 212, 0.16);\n            border: 1px solid rgba(34, 211, 238, 0.45);\n            color: #22d3ee;\n            font-size: 0.72rem;\n            font-weight: 700;\n            padding: 2px 9px;\n            border-radius: 999px;\n            font-family: \'JetBrains Mono\', monospace;\n        }\n        .ns-brand-sub {\n            font-size: 0.84rem;\n            color: #94a3b8;\n            margin-top: 2px;\n        }\n\n        /* Live Monitor Indicator */\n        .ns-status-pill {\n            display: inline-flex;\n            align-items: center;\n            gap: 9px;\n            padding: 7px 15px;\n            border-radius: 999px;\n            font-size: 0.8rem;\n            font-weight: 700;\n            letter-spacing: 0.06em;\n            text-transform: uppercase;\n        }\n        .ns-status-live {\n            background: rgba(16, 185, 129, 0.16);\n            border: 1px solid rgba(16, 185, 129, 0.55);\n            color: #34d399;\n            box-shadow: 0 0 18px rgba(16, 185, 129, 0.25);\n        }\n        .ns-status-stopped {\n            background: rgba(148, 163, 184, 0.12);\n            border: 1px solid rgba(148, 163, 184, 0.32);\n            color: #94a3b8;\n        }\n        .ns-dot-live {\n            width: 9px;\n            height: 9px;\n            border-radius: 50%;\n            background: #10b981;\n            box-shadow: 0 0 10px #10b981;\n            animation: nsPulse 1.6s infinite;\n        }\n        .ns-dot-stopped {\n            width: 9px;\n            height: 9px;\n            border-radius: 50%;\n            background: #64748b;\n        }\n        @keyframes nsPulse {\n            0% { transform: scale(0.95); opacity: 0.75; }\n            50% { transform: scale(1.2); opacity: 1; }\n            100% { transform: scale(0.95); opacity: 0.75; }\n        }\n\n        /* Page Title Block */\n        .ns-page-title {\n            font-size: 1.65rem;\n            font-weight: 800;\n            color: #f8fafc;\n            margin-bottom: 2px;\n        }\n        .ns-page-subtitle {\n            font-size: 0.94rem;\n            color: #94a3b8;\n            margin-bottom: 16px;\n        }\n\n        /* SOC Cards & Panels */\n        .ns-card {\n            background: linear-gradient(180deg, #101b33 0%, #0c1427 100%);\n            border: 1px solid var(--border-subtle);\n            border-radius: 12px;\n            padding: 16px 18px;\n            box-shadow: 0 6px 20px rgba(2, 6, 23, 0.45);\n        }\n        .ns-kpi-card {\n            background: linear-gradient(165deg, #111e38 0%, #0b1324 100%);\n            border: 1px solid rgba(59, 130, 246, 0.26);\n            border-radius: 12px;\n            padding: 15px 16px;\n            min-height: 102px;\n            display: flex;\n            flex-direction: column;\n            justify-content: space-between;\n            box-shadow: 0 6px 18px rgba(2, 6, 23, 0.42);\n        }\n        .ns-kpi-label {\n            font-size: 0.78rem;\n            font-weight: 600;\n            text-transform: uppercase;\n            letter-spacing: 0.05em;\n            color: #94a3b8;\n        }\n        .ns-kpi-value {\n            font-size: 1.72rem;\n            font-weight: 800;\n            color: #f8fafc;\n            margin-top: 6px;\n            font-family: \'JetBrains Mono\', monospace;\n        }\n        .ns-kpi-sub {\n            font-size: 0.75rem;\n            color: #64748b;\n            margin-top: 4px;\n        }\n\n        /* Dedicated Detection Rule Panel (Section 8.C) */\n        .ns-rule-panel {\n            background: linear-gradient(145deg, #0b1936 0%, #0e2247 55%, #09152d 100%);\n            border: 1.5px solid rgba(34, 211, 238, 0.55);\n            border-left: 5px solid #22d3ee;\n            border-radius: 12px;\n            padding: 18px 20px;\n            box-shadow: 0 8px 26px rgba(6, 182, 212, 0.14);\n            height: 100%;\n        }\n        .ns-rule-header {\n            display: flex;\n            align-items: center;\n            gap: 10px;\n            font-size: 0.85rem;\n            font-weight: 700;\n            text-transform: uppercase;\n            letter-spacing: 0.08em;\n            color: #22d3ee;\n            margin-bottom: 8px;\n        }\n        .ns-rule-metric {\n            font-size: 1.32rem;\n            font-weight: 800;\n            color: #ffffff;\n            font-family: \'JetBrains Mono\', monospace;\n            margin-bottom: 6px;\n        }\n        .ns-rule-desc {\n            font-size: 0.88rem;\n            color: #cbd5e1;\n            line-height: 1.45;\n        }\n\n        /* Detection Scope Blue Info Panel (Section 8.D) */\n        .ns-scope-panel {\n            background: linear-gradient(135deg, rgba(37, 99, 235, 0.16) 0%, rgba(6, 182, 212, 0.10) 100%);\n            border: 1px solid rgba(59, 130, 246, 0.45);\n            border-left: 4px solid #3b82f6;\n            border-radius: 11px;\n            padding: 14px 18px;\n            margin: 14px 0 18px 0;\n            color: #e2e8f0;\n            font-size: 0.89rem;\n            line-height: 1.55;\n        }\n\n        /* Admin Status Banners (Section 8.A) */\n        .ns-admin-ok {\n            background: rgba(16, 185, 129, 0.13);\n            border: 1px solid rgba(16, 185, 129, 0.48);\n            border-left: 4px solid #10b981;\n            border-radius: 10px;\n            padding: 12px 16px;\n            color: #d1fae5;\n            font-size: 0.9rem;\n            margin-bottom: 14px;\n        }\n        .ns-admin-warn {\n            background: rgba(245, 158, 11, 0.14);\n            border: 1px solid rgba(245, 158, 11, 0.5);\n            border-left: 4px solid #f59e0b;\n            border-radius: 10px;\n            padding: 12px 16px;\n            color: #fef3c7;\n            font-size: 0.9rem;\n            margin-bottom: 14px;\n        }\n\n        /* Dark-Red Notification Box (Section 8.J) */\n        .ns-alert-error {\n            background: #2b0d14;\n            border: 1px solid rgba(239, 68, 68, 0.55);\n            border-radius: 10px;\n            padding: 12px 16px;\n            color: #fecaca;\n            font-size: 0.9rem;\n            font-weight: 500;\n            box-shadow: 0 6px 20px rgba(127, 29, 29, 0.35);\n        }\n\n        /* Center Streamlit Toast Pop-ups at Top-Middle */\n        [data-testid="stToastContainer"] {\n            top: 1.25rem !important;\n            left: 50% !important;\n            right: auto !important;\n            transform: translateX(-50%) !important;\n            align-items: center !important;\n            z-index: 999999 !important;\n        }\n        [data-testid="stToast"] {\n            background: linear-gradient(135deg, #0d1933 0%, #13254a 100%) !important;\n            border: 1px solid rgba(34, 211, 238, 0.55) !important;\n            border-left: 4px solid #22d3ee !important;\n            border-radius: 12px !important;\n            box-shadow: 0 12px 32px rgba(2, 6, 23, 0.85) !important;\n            color: #f8fafc !important;\n            min-width: 340px;\n            max-width: 540px;\n        }\n        [data-testid="stToast"] div,\n        [data-testid="stToast"] p,\n        [data-testid="stToast"] span {\n            color: #f8fafc !important;\n            font-weight: 600 !important;\n        }\n\n        /* Status Badges */\n        .ns-badge {\n            display: inline-block;\n            padding: 3px 10px;\n            border-radius: 999px;\n            font-size: 0.74rem;\n            font-weight: 700;\n            letter-spacing: 0.04em;\n            text-transform: uppercase;\n            font-family: \'JetBrains Mono\', monospace;\n        }\n        .ns-badge-green {\n            background: rgba(16, 185, 129, 0.16);\n            border: 1px solid rgba(16, 185, 129, 0.45);\n            color: #34d399;\n        }\n        .ns-badge-amber {\n            background: rgba(245, 158, 11, 0.16);\n            border: 1px solid rgba(245, 158, 11, 0.45);\n            color: #fbbf24;\n        }\n        .ns-badge-red {\n            background: rgba(239, 68, 68, 0.18);\n            border: 1px solid rgba(239, 68, 68, 0.5);\n            color: #f87171;\n        }\n        .ns-badge-grey {\n            background: rgba(148, 163, 184, 0.14);\n            border: 1px solid rgba(148, 163, 184, 0.35);\n            color: #cbd5e1;\n        }\n\n        /* Styled HTML Security Tables */\n        .ns-table-wrap {\n            width: 100%;\n            overflow-x: auto;\n            border: 1px solid #263b59;\n            border-radius: 12px;\n            background: #0b1324;\n            margin-top: 8px;\n        }\n        table.ns-table {\n            width: 100%;\n            border-collapse: collapse;\n            table-layout: auto;\n            font-size: 0.82rem;\n        }\n        table.ns-table thead tr {\n            background: #101e3b;\n            border-bottom: 1px solid rgba(56, 189, 248, 0.3);\n        }\n        table.ns-table th {\n            text-align: left;\n            padding: 12px 13px;\n            color: #38bdf8;\n            font-weight: 750;\n            font-size: 0.74rem;\n            text-transform: uppercase;\n            letter-spacing: 0.04em;\n            white-space: nowrap;\n        }\n        table.ns-table td {\n            padding: 13px;\n            border-bottom: 1px solid rgba(38, 59, 89, 0.8);\n            color: #dbe5f2;\n            vertical-align: middle;\n            overflow-wrap: anywhere;\n        }\n        table.ns-table tbody tr:last-child td {\n            border-bottom: 0;\n        }\n        table.ns-table tbody tr:hover {\n            background: rgba(37, 99, 235, 0.08);\n        }\n        .ns-mono {\n            font-family: \'JetBrains Mono\', monospace;\n            font-size: 0.82rem;\n        }\n\n        /* Slide-Out Hamburger Drawer */\n        .ns-drawer-panel {\n            background: linear-gradient(180deg, #091124 0%, #0d1730 100%);\n            border: 1px solid rgba(34, 211, 238, 0.42);\n            border-radius: 14px;\n            padding: 16px 14px;\n            width: 280px;\n            max-width: 100%;\n            box-shadow: 0 18px 42px rgba(2, 6, 23, 0.85);\n            margin-bottom: 14px;\n        }\n        .ns-drawer-title {\n            font-size: 0.78rem;\n            font-weight: 700;\n            text-transform: uppercase;\n            letter-spacing: 0.08em;\n            color: #22d3ee;\n            margin-bottom: 10px;\n            padding-left: 6px;\n        }\n\n        /* Reusable Common Footer (Section 13) */\n        .ns-footer {\n            margin-top: 34px;\n            padding: 18px 20px;\n            background: #091022;\n            border: 1px solid rgba(56, 189, 248, 0.2);\n            border-radius: 12px;\n            text-align: center;\n        }\n        .ns-footer-line1 {\n            font-size: 0.82rem;\n            color: #94a3b8;\n            margin-bottom: 6px;\n        }\n        .ns-footer-line2 {\n            font-size: 0.9rem;\n            font-weight: 700;\n            color: #22d3ee;\n            letter-spacing: 0.03em;\n            margin-bottom: 3px;\n        }\n        .ns-footer-line3 {\n            font-size: 0.8rem;\n            color: #cbd5e1;\n        }\n\n        /* Streamlit widget styling refinements */\n        div[data-baseweb="select"] > div,\n        div[data-baseweb="input"] > div {\n            background-color: #0d172e !important;\n            border-color: rgba(56, 189, 248, 0.32) !important;\n            color: #f8fafc !important;\n        }\n        .stButton > button {\n            border-radius: 9px !important;\n            font-weight: 600 !important;\n            border: 1px solid rgba(56, 189, 248, 0.35) !important;\n            background-color: #101e3b !important;\n            color: #f8fafc !important;\n            transition: all 0.15s ease;\n        }\n        .stButton > button:hover:not(:disabled) {\n            border-color: #22d3ee !important;\n            background-color: #162a52 !important;\n        }\n        .stButton > button[kind="primary"] {\n            background: linear-gradient(135deg, #2563eb 0%, #0284c7 100%) !important;\n            border: 1px solid #38bdf8 !important;\n            color: #ffffff !important;\n        }\n        .stButton > button:disabled {\n            opacity: 0.42 !important;\n            cursor: not-allowed !important;\n        }\n        </style>\n        ', unsafe_allow_html=True)

def escape_html(value: object) -> str:
    return html.escape(str(value if value is not None else ''))

def render_kpi_row(cards: List[Dict[str, Any]]) -> None:
    """Render a responsive row of dark SOC KPI cards."""
    cols = st.columns(len(cards))
    for col, card in zip(cols, cards):
        accent = card.get('accent', '#38bdf8')
        sub = escape_html(card.get('subtitle', ''))
        sub_html = f'<div class="ns-kpi-sub">{sub}</div>' if sub else ''
        with col:
            st.markdown(f"""\n                <div class="ns-kpi-card" style="border-top: 3px solid {accent};">\n                    <div class="ns-kpi-label">{escape_html(card['label'])}</div>\n                    <div class="ns-kpi-value" style="color:{accent};">{escape_html(card['value'])}</div>\n                    {sub_html}\n                </div>\n                """, unsafe_allow_html=True)

def render_detection_rule_panel(port_threshold: int, window_seconds: int) -> None:
    """
    Section 8.C: Dedicated bordered Detection Rule panel beside Network Interface controls.
    Always visible even when monitoring is stopped, reading values dynamically from backend config.
    """
    st.markdown(f'\n        <div class="ns-rule-panel">\n            <div class="ns-rule-header">\n                <span>{SVG_3D_RADAR_SCAN}</span>\n                <span>Detection Rule</span>\n            </div>\n            <div class="ns-rule-metric">{int(port_threshold)} unique TCP ports / {int(window_seconds)} seconds</div>\n            <div class="ns-rule-desc">Initial TCP SYN packets grouped by source IP.</div>\n        </div>\n        ', unsafe_allow_html=True)

def render_detection_scope_disclaimer() -> None:
    """Section 8.D: Separate blue information panel with exact required wording."""
    st.markdown(f'<div class="ns-scope-panel">{escape_html(DETECTION_SCOPE_DISCLAIMER)}</div>', unsafe_allow_html=True)

def status_badge_html(status_text: str, event_type: str='') -> str:
    """
    Return visually distinct status pill HTML:
- Green: Successful / Active
- Amber: Pending
- Red: Failed or Blocked (with clear textual distinction)
- Grey: Skipped or Informational
    """
    upper_status = (status_text or '').upper()
    upper_event = (event_type or '').upper()
    if upper_status in ('SUCCESSFUL', 'ACTIVE') or upper_event == 'UNBLOCKED':
        css_cls = 'ns-badge-green'
        label = 'SUCCESSFUL' if upper_status == 'SUCCESSFUL' else upper_status
    elif upper_status == 'PENDING' or 'PENDING' in upper_event:
        css_cls = 'ns-badge-amber'
        label = 'PENDING'
    elif upper_status == 'FAILED' or 'FAILED' in upper_event or 'ERROR' in upper_event:
        css_cls = 'ns-badge-red'
        label = 'FAILED'
    elif upper_event == 'BLOCKED':
        css_cls = 'ns-badge-red'
        label = 'BLOCKED'
    else:
        css_cls = 'ns-badge-grey'
        label = upper_status or 'INFORMATIONAL'
    return f'<span class="ns-badge {css_cls}">{escape_html(label)}</span>'

def set_notification(message: str, level: str='error') -> None:
    st.session_state['ns_notification'] = {'message': message, 'level': level}

def clear_notification() -> None:
    st.session_state['ns_notification'] = None

def render_notifications() -> None:
    """
    Render active dismissible notification banner (Section 8.J).
    Dark-red box with subtle red border, rounded corners, and close button.
    """
    notif = st.session_state.get('ns_notification')
    if not notif:
        return
    msg = escape_html(notif.get('message', ''))
    col_msg, col_btn = st.columns([9.3, 0.7])
    with col_msg:
        st.markdown(f'<div class="ns-alert-error">{msg}</div>', unsafe_allow_html=True)
    with col_btn:
        if st.button('✕', key='ns_close_notif_btn', help='Dismiss notification'):
            clear_notification()
            st.rerun()

def render_header(is_monitoring_live: bool) -> None:
    """
    Render the NetSentry | PortShield header with 3D logo, version badge,
    product description, and accurate LIVE / STOPPED monitoring indicator.
    """
    if is_monitoring_live:
        status_html = '<div class="ns-status-pill ns-status-live"><span class="ns-dot-live"></span><span>LIVE MONITOR</span></div>'
    else:
        status_html = '<div class="ns-status-pill ns-status-stopped"><span class="ns-dot-stopped"></span><span>STOPPED</span></div>'
    st.markdown(f'\n        <div class="ns-header">\n            <div class="ns-header-left">\n                <div>{SVG_3D_SHIELD_LOGO}</div>\n                <div>\n                    <div class="ns-brand-title">\n                        <span>{PROJECT_NAME}</span>\n                        <span class="ns-version-badge">{APP_VERSION}</span>\n                    </div>\n                    <div class="ns-brand-sub">{PRODUCT_NAME} &bull; {MAIN_TITLE}</div>\n                </div>\n            </div>\n            <div>{status_html}</div>\n        </div>\n        ', unsafe_allow_html=True)

def render_footer() -> None:
    """
    Render the common footer in the exact required content order:
1. Authorized defensive monitoring disclaimer
2. NetSentry | PortShield | v1.0.0
3. Network Threat Detection & Automated Response
    """
    st.markdown(f'\n        <div class="ns-footer">\n            <div class="ns-footer-line1">{FOOTER_DISCLAIMER}</div>\n            <div class="ns-footer-line2">{PROJECT_NAME} | {PRODUCT_NAME} | {APP_VERSION}</div>\n            <div class="ns-footer-line3">{MAIN_TITLE}</div>\n        </div>\n        ', unsafe_allow_html=True)

PLACEHOLDER_INTERFACE = 'Select a network adapter'

def _ports_from_event(event):
    import re
    details = str(event.get('detection_details') or '')
    match = re.search('Scanned destination ports:\\s*([0-9, ]+)', details, re.I)
    if not match:
        match = re.search('observed ports:\\s*([0-9, ]+)', details, re.I)
    if not match:
        return '—'
    ports = sorted({int(x) for x in re.findall('\\d+', match.group(1))})
    return ', '.join(map(str, ports)) if ports else '—'

def _group_consecutive_findings(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse consecutive events with the same (event_type, source_ip, firewall_status) into a single summary row."""
    grouped: List[Dict[str, Any]] = []
    for ev in events:
        key = (
            str(ev.get('event_type') or '—'),
            str(ev.get('source_ip') or '—'),
            str(ev.get('firewall_status') or '—'),
        )
        ev_num = int(ev.get('event_id') or 0)
        ports_count = int(ev.get('unique_ports') or 0)
        if grouped and grouped[-1]['_key'] == key:
            bucket = grouped[-1]
            bucket['end_id'] = ev_num
            bucket['timestamp'] = ev.get('timestamp') or bucket['timestamp']
            bucket['unique_ports'] = max(bucket['unique_ports'], ports_count)
            bucket['details'] = ev.get('detection_details') or bucket['details']
        else:
            grouped.append({
                '_key': key,
                'start_id': ev_num,
                'end_id': ev_num,
                'timestamp': ev.get('timestamp') or '—',
                'event_type': key[0],
                'source_ip': key[1],
                'unique_ports': ports_count,
                'firewall_status': key[2],
                'details': ev.get('detection_details') or '—',
            })
    for item in grouped:
        if item['start_id'] == item['end_id']:
            item['event_id_range'] = f"EVT-{item['start_id']:06d}"
        else:
            item['event_id_range'] = f"EVT-{item['start_id']:06d} to EVT-{item['end_id']:06d}"
    return grouped

def _duration_seconds(start, end):
    try:
        return max(0.0, (datetime.fromisoformat(str(end)) - datetime.fromisoformat(str(start))).total_seconds())
    except (TypeError, ValueError):
        return 0.0

def _current_csv(scan_id, investigation, events):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['NetSentry | PortShield - Current Investigation Report'])
    writer.writerow(['Report Scope', 'Current investigation only'])
    writer.writerow(['Scan ID', scan_id])
    writer.writerow(['Selected Network Adapter', investigation.get('network_interface', '—')])
    writer.writerow(['Npcap Device ID', investigation.get('network_interface', '—')])
    writer.writerow(['Start Time', investigation.get('start_time', '—')])
    writer.writerow(['End Time', investigation.get('end_time', '—')])
    writer.writerow(['Duration (seconds)', f"{_duration_seconds(investigation.get('start_time'), investigation.get('end_time')):.2f}"])
    writer.writerow(['Investigation Status', investigation.get('status', '—')])
    writer.writerow([])
    writer.writerow(['Event ID', 'Timestamp', 'Event', 'Source IP', 'Unique Ports', 'Ports Scanned', 'Firewall Status', 'Details'])
    for event in events:
        writer.writerow([f"EVT-{int(event.get('event_id') or 0):06d}", event.get('timestamp', ''), event.get('event_type', ''), event.get('source_ip', ''), event.get('unique_ports', 0), _ports_from_event(event), event.get('firewall_status', ''), event.get('detection_details', '')])
    return output.getvalue()

def render_investigate_page(monitoring_service: MonitoringService, history_service: HistoryService, report_service: ReportService) -> None:
    st.markdown('<div class="ns-page-title">Network Investigation</div><div class="ns-page-subtitle">Monitor network traffic, detect TCP SYN port scanning and review the current investigation.</div>', unsafe_allow_html=True)
    env = monitoring_service.get_environment_status()
    rule_cfg = monitoring_service.get_detection_rule_config()
    if env['is_admin']:
        st.markdown('<div class="ns-admin-ok"><strong>Administrator Privileges Active:</strong> NetSentry can capture packets and manage Windows Defender Firewall rules.</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="ns-admin-warn"><strong>Administrator Privileges Required:</strong> Run Streamlit as Administrator for packet capture and firewall enforcement.</div>', unsafe_allow_html=True)
    if not env['capture_ready']:
        st.markdown(f"""<div class="ns-admin-warn"><strong>Packet Capture Notice:</strong> {escape_html(env['capture_message'])}</div>""", unsafe_allow_html=True)
    running = monitoring_service.is_running
    scan_id = st.session_state.get('ns_active_scan_id') or monitoring_service.current_scan_id
    investigation = monitoring_service.get_investigation_details(scan_id) if scan_id else None
    if running:
        lifecycle = 'RUNNING'
    elif scan_id and investigation and (investigation.get('status') in {'COMPLETED', 'INTERRUPTED', 'FAILED'}):
        lifecycle = 'COMPLETED'
    else:
        lifecycle = 'READY'
    st.markdown('<div class="ns-card" style="margin-bottom:12px;padding:18px 20px;"><div style="font-size:1.28rem;font-weight:800;color:#e2e8f0;">Monitoring Controls</div></div>', unsafe_allow_html=True)
    interfaces = env.get('interfaces', [])
    labels = env.get('interface_label_map', {})
    if 'ns_iface_select' not in st.session_state:
        st.session_state['ns_iface_select'] = PLACEHOLDER_INTERFACE
    if st.session_state.get('ns_reset_interface'):
        st.session_state['ns_iface_select'] = PLACEHOLDER_INTERFACE
        st.session_state['ns_reset_interface'] = False

    def fmt(value):
        if value == PLACEHOLDER_INTERFACE:
            return PLACEHOLDER_INTERFACE
        return next((name for name, device in allowed.items() if device == value), labels.get(value, value))
    allowed = {}
    for device in interfaces:
        label = str(labels.get(device, device)).lower()
        short = 'WSL' if 'wsl' in label or 'hyper-v' in label else 'Wi-Fi' if 'wi-fi' in label or 'wifi' in label or 'wireless' in label else None
        if short and short not in allowed:
            allowed[short] = device
    options = [PLACEHOLDER_INTERFACE] + [allowed[x] for x in ('Wi-Fi', 'WSL') if x in allowed]
    default_index = 0
    if lifecycle == 'READY' and st.session_state.get('ns_iface_select') in options:
        default_index = options.index(st.session_state['ns_iface_select'])
    elif lifecycle == 'READY' and interfaces:
        default_index = min(int(env.get('suggested_interface_index', 0)) + 1, len(interfaces))
    interface_disabled = lifecycle != 'READY' or not interfaces
    selected_interface = st.selectbox('Network adapter', options=options, index=default_index, format_func=fmt, placeholder=PLACEHOLDER_INTERFACE, label_visibility='collapsed', disabled=interface_disabled, key='ns_iface_select')
    if selected_interface != PLACEHOLDER_INTERFACE and selected_interface:
        st.caption(f'Npcap Device ID: `{selected_interface}`')
    elif not interfaces:
        st.caption('No Npcap-compatible network adapters were detected. Check Npcap installation and permissions.')
    c1, c2, c3 = st.columns(3, gap='medium')
    with c1:
        start_clicked = st.button('Start Monitoring', type='primary', use_container_width=True, disabled=lifecycle != 'READY' or not interfaces or selected_interface == PLACEHOLDER_INTERFACE, key='ns_start_monitor_btn')
    with c2:
        stop_clicked = st.button('Stop Monitoring', use_container_width=True, disabled=lifecycle != 'RUNNING', key='ns_stop_monitor_btn')
    with c3:
        new_clicked = st.button('New Investigation', use_container_width=True, disabled=lifecycle != 'COMPLETED', key='ns_new_investigation_btn')
    if start_clicked:
        try:
            clear_notification()
            new_scan_id = monitoring_service.start_monitoring(selected_interface)
            st.session_state['ns_active_scan_id'] = new_scan_id
            st.session_state['last_active_scan_id'] = new_scan_id
            st.session_state['ns_show_monitor_toast'] = True
            st.rerun()
        except Exception as exc:
            set_notification(str(exc), level='error')
            st.rerun()
    if stop_clicked:
        clear_notification()
        completed = monitoring_service.stop_monitoring()
        if completed:
            st.session_state['ns_active_scan_id'] = completed.get('scan_id')
            st.session_state['last_active_scan_id'] = completed.get('scan_id')
            st.session_state['ns_show_complete_toast'] = True
        st.rerun()
    if new_clicked:
        monitoring_service.reset_current_session()
        st.session_state['ns_active_scan_id'] = None
        st.session_state['last_active_scan_id'] = None
        st.session_state['ns_reset_interface'] = True
        clear_notification()
        st.rerun()
    if lifecycle == 'RUNNING':
        st.markdown('<div class="ns-admin-ok" style="margin-top:12px;">\n        <strong>Monitoring in Progress</strong> — Live packet capture is active. Please wait for the monitoring process to complete or select Stop Monitoring when ready.\n        <div style="height:6px;background:rgba(34,211,238,.18);border-radius:8px;margin-top:10px;overflow:hidden;">\n        <div style="height:6px;width:38%;background:#22d3ee;border-radius:8px;animation:ns-progress 1.6s ease-in-out infinite alternate;"></div></div>\n        </div><style>@keyframes ns-progress{from{transform:translateX(0)}to{transform:translateX(155%)}}</style>', unsafe_allow_html=True)
    elif lifecycle == 'COMPLETED':
        st.markdown('<div class="ns-admin-ok" style="margin-top:12px;"><strong>Investigation Completed Successfully</strong> — The current investigation has been saved. Select New Investigation to start another session.</div>', unsafe_allow_html=True)
    if st.session_state.pop('ns_show_monitor_toast', False):
        st.toast('Current monitoring is in progress. Please wait for the process to complete.', icon='🔎')
    if st.session_state.pop('ns_show_complete_toast', False):
        st.toast('Investigation completed successfully.', icon='✅')
    render_notifications()
    render_detection_rule_panel(port_threshold=rule_cfg['port_threshold'], window_seconds=rule_cfg['window_seconds'])
    if not scan_id:
        st.info('No Recent Investigation. Select a network adapter and click Start Monitoring to begin.')
    else:
        investigation = monitoring_service.get_investigation_details(scan_id) or investigation or {}
        events = monitoring_service.get_events_for_scan(scan_id)
        overview = monitoring_service.get_current_session_overview_for(scan_id)
        ports_by_ip = {}
        for event in events:
            import re
            text = str(event.get('detection_details') or '')
            match = re.search('Scanned destination ports:\\s*([0-9, ]+)', text, re.I)
            if match:
                ip = event.get('source_ip')
                ports_by_ip.setdefault(ip, set()).update((int(x) for x in re.findall('\\d+', match.group(1))))
        total_unique_ports = len(set().union(*ports_by_ip.values())) if ports_by_ip else 0
        duration = _duration_seconds(investigation.get('start_time'), investigation.get('end_time')) if investigation.get('end_time') else (datetime.now() - datetime.fromisoformat(investigation['start_time'])).total_seconds() if investigation.get('start_time') else 0
        adapter = fmt(investigation.get('network_interface'))
        st.markdown('### Investigation Overview')
        kpis = [('Total Events', overview['total_events'], '#38bdf8'), ('Unique Source IPs', overview['unique_source_ips'], '#22d3ee'), ('Successfully Blocked IPs', overview['successful_blocks'], '#10b981'), ('Blocks Pending', overview['pending_blocks'], '#f59e0b')]
        cols = st.columns(4, gap='small')
        for col, (label, value, accent) in zip(cols, kpis):
            with col:
                st.markdown(f'<div class="ns-card" style="border-top:3px solid {accent};min-height:105px;padding:13px;"><div style="font-size:.72rem;color:#94a3b8;font-weight:750;text-transform:uppercase;">{label}</div><div style="font-size:1.8rem;font-weight:800;color:{accent};margin-top:8px;">{value}</div></div>', unsafe_allow_html=True)
        st.markdown('### Current Security Findings')
        if events:
            findings_columns = [
                'Event ID', 'Timestamp', 'Event', 'Source IP',
                'Unique Ports', 'Firewall Status', 'Details'
            ]
            head_html = ''.join((f'<th>{escape_html(col)}</th>' for col in findings_columns))
            body_rows = []
            for item in _group_consecutive_findings(events):
                row_values = [
                    item['event_id_range'],
                    item['timestamp'],
                    item['event_type'],
                    item['source_ip'],
                    item['unique_ports'],
                    item['firewall_status'],
                    item['details'],
                ]
                cells_html = ''.join((f'<td>{escape_html(val)}</td>' for val in row_values))
                body_rows.append(f'<tr>{cells_html}</tr>')
            st.markdown(
                f'''
                <div class="ns-table-wrap">
                    <table class="ns-table">
                        <thead><tr>{head_html}</tr></thead>
                        <tbody>{''.join(body_rows)}</tbody>
                    </table>
                </div>
                ''',
                unsafe_allow_html=True,
            )
        else:
            st.info('No security findings have been recorded in this investigation yet.')
        st.markdown('### Report Metadata')
        metadata = [('Selected Network Adapter', adapter), ('Npcap Device ID', investigation.get('network_interface', '—')), ('Scan ID', scan_id), ('Start Time', investigation.get('start_time', '—')), ('End Time', investigation.get('end_time') or ('Monitoring in progress' if running else '—')), ('Time Taken', f'{duration:.2f} seconds'), ('Investigation Status', investigation.get('status', 'RUNNING'))]
        st.markdown('<div class="ns-card ns-metadata-vertical">' + ''.join((f'<div><span>{escape_html(k)}</span><strong>{escape_html(v)}</strong></div>' for k, v in metadata)) + '</div>', unsafe_allow_html=True)
        csv_data = _current_csv(scan_id, investigation, events)
        st.markdown("<div style='height:26px'></div>", unsafe_allow_html=True)
        dl1, dl2 = st.columns(2, gap='medium')
        with dl1:
            st.download_button('Download Current Investigation as CSV', csv_data.encode('utf-8-sig'), file_name=f'NetSentry_{scan_id}.csv', mime='text/csv', use_container_width=True, disabled=running, key='ns_current_csv')
        with dl2:
            if not running:
                try:
                    pdf_data = report_service.generate_investigation_pdf_bytes(scan_id)
                    st.download_button('Download Current Investigation as PDF', pdf_data, file_name=f'NetSentry_{scan_id}.pdf', mime='application/pdf', use_container_width=True, key='ns_current_pdf')
                except Exception as exc:
                    st.button('PDF Report Unavailable', disabled=True, use_container_width=True)
                    st.caption(str(exc))
            else:
                st.button('PDF Available After Completion', disabled=True, use_container_width=True)
    if running:
        try:
            from streamlit_autorefresh import st_autorefresh
            st_autorefresh(interval=AUTO_REFRESH_INTERVAL_MS, key='ns_investigate_autorefresh')
        except Exception:
            pass

def _build_investigation_rows(events, scans):
    by_scan = {}
    for event in events:
        by_scan.setdefault(str(event.get('scan_id', '')), []).append(event)
    rows = []
    for scan in scans:
        sid = str(scan.get('scan_id', ''))
        evs = by_scan.get(sid, [])
        ips = sorted({str(e.get('source_ip')) for e in evs if e.get('source_ip') not in (None, '', '-')})
        ports = set()
        for e in evs:
            match = re.search('(?:Scanned destination ports|observed ports):\\s*([0-9, ]+)', str(e.get('detection_details', '')), re.I)
            if match:
                ports.update(int(p) for p in re.findall('\\d+', match.group(1)))
        unique_ports_count = max([len(ports)] + [int(e.get('unique_ports') or 0) for e in evs])
        event_ids = [f"EVT-{int(e['event_id']):06d}" for e in evs if e.get('event_id') is not None]
        latest = evs[0] if evs else {}
        statuses = {str(e.get('firewall_status', '')).upper() for e in evs}
        status = 'UNBLOCKED' if 'UNBLOCKED' in statuses else 'SUCCESSFUL' if 'SUCCESSFUL' in statuses else 'FAILED' if 'FAILED' in statuses else 'PENDING' if 'PENDING' in statuses else 'NO EVENTS' if not evs else 'RECORDED'
        rows.append({'Scan ID': sid, 'Timestamp': scan.get('start_time') or scan.get('created_at') or latest.get('timestamp', '—'), 'Source IP': ', '.join(ips) or '—', 'Events': len(evs), 'Unique Ports': unique_ports_count, 'Event IDs': ', '.join(event_ids) or '—', 'Firewall Status': status, 'Details': str(latest.get('detection_details') or scan.get('status') or 'No security events recorded')[:180]})
    return rows

def _all_findings_csv(rows):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['Scan ID', 'Timestamp', 'Source IP', 'Events', 'Unique Ports', 'Event IDs', 'Firewall Status', 'Details'])
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode('utf-8-sig')

def render_dashboard_page(monitoring_service: MonitoringService, history_service=None, report_service=None) -> None:
    st.markdown('<style>\n    .dash-kpi{background:linear-gradient(145deg,#14243b,#0b1527);border:1px solid #29415f;border-top:3px solid #38bdf8;border-radius:12px;padding:15px 16px;min-height:112px;}\n    .dash-label{font-size:.76rem;color:#9aabc1;font-weight:750;letter-spacing:.04em;text-transform:uppercase;}\n    .dash-value{font-size:1.85rem;color:#e2e8f0;font-weight:800;margin-top:8px;}\n    .dash-head{color:#38bdf8;font-size:.78rem;font-weight:800;text-transform:uppercase;padding:8px 5px;border-bottom:1px solid #29415f;}\n    .dash-cell{color:#dbe5f2;font-size:.78rem;padding:10px 5px;overflow-wrap:anywhere;}\n    .ns-section-subtitle{color:#94a3b8;font-size:.94rem;margin-top:-.25rem;margin-bottom:1.25rem;}\n    .ns-section-gap{height:30px;}\n    /* Keep every All Investigations control in the same dark SOC visual system. */\n    [data-testid="stTextInput"] input,\n    [data-testid="stSelectbox"] [data-baseweb="select"] > div {\n        background:#0d172e !important;\n        color:#e2e8f0 !important;\n        border:1px solid rgba(56,189,248,.32) !important;\n        border-radius:9px !important;\n        min-height:44px;\n        height:44px;\n    }\n    [data-testid="stSelectbox"] [data-baseweb="select"] {\n        background:transparent !important;\n    }\n    [data-testid="stSelectbox"] [data-baseweb="select"] div,\n    [data-testid="stSelectbox"] [data-baseweb="select"] span,\n    [data-testid="stSelectbox"] [data-baseweb="select"] svg {\n        color:#e2e8f0 !important;\n        fill:#e2e8f0 !important;\n    }\n    [data-testid="stTextInput"] input::placeholder {color:#94a3b8 !important;opacity:1;}\n    [data-testid="stDownloadButton"] button {\n        min-height:44px;height:44px;border-radius:9px !important;font-weight:650 !important;\n        border:1px solid rgba(56,189,248,.35) !important;\n        background:#101e3b !important;color:#f8fafc !important;\n    }\n    [data-testid="stDownloadButton"] button:hover {\n        border-color:#22d3ee !important;background:#162a52 !important;\n    }\n    .ns-investigations-table {width:100%;overflow-x:auto;border:1px solid #263b59;\n        border-radius:12px;background:#0b1324;margin-top:8px;}\n    .ns-investigations-table table {width:100%;border-collapse:collapse;\n        table-layout:auto;font-size:.82rem;}\n    .ns-investigations-table thead tr {background:#101e3b;\n        border-bottom:1px solid rgba(56,189,248,.3);}\n    .ns-investigations-table th {text-align:left;padding:12px 13px;color:#38bdf8;\n        font-weight:750;font-size:.74rem;text-transform:uppercase;letter-spacing:.04em;\n        white-space:nowrap;}\n    .ns-investigations-table td {padding:13px;border-bottom:1px solid rgba(38,59,89,.8);\n        color:#dbe5f2;vertical-align:middle;overflow-wrap:anywhere;}\n    .ns-investigations-table tbody tr:last-child td {border-bottom:0;}\n    .ns-investigations-table tbody tr:hover {background:rgba(37,99,235,.08);}\n    .ns-empty-row td {text-align:center !important;color:#94a3b8 !important;padding:18px 13px !important;font-style:normal;}\n    </style>', unsafe_allow_html=True)
    snap = monitoring_service.get_dashboard_snapshot()
    metrics, events, scans = (snap['metrics'], snap['events'], snap['investigations'])
    st.markdown('### Network Security Overview')
    st.markdown('<div class="ns-section-subtitle">A live summary of recorded investigations, detected network events, and firewall response activity.</div>', unsafe_allow_html=True)
    blocked_scan_ids = {str(e.get('scan_id')) for e in events if str(e.get('event_type', '')).upper() == 'BLOCKED' and str(e.get('firewall_status', '')).upper() == 'SUCCESSFUL'}
    render_kpi_row([{'label': 'Total Investigations', 'value': metrics.get('total_investigations', len(scans)), 'subtitle': 'Unique Scan ID sessions', 'accent': '#22d3ee'}, {'label': 'Total Events', 'value': metrics.get('total_events', len(events)), 'subtitle': 'All recorded security events', 'accent': '#38bdf8'}, {'label': 'Blocked Investigations', 'value': len(blocked_scan_ids), 'subtitle': 'Investigations with successful blocks', 'accent': '#10b981'}, {'label': 'Blocks Pending', 'value': metrics.get('pending_blocks', 0), 'subtitle': 'Awaiting firewall completion', 'accent': '#f59e0b'}])
    st.markdown('<div class="ns-section-gap"></div>', unsafe_allow_html=True)
    st.markdown('### All Investigations')
    st.markdown('<div class="ns-section-subtitle">A complete record of every network monitoring investigation, including sessions with no detected events.</div>', unsafe_allow_html=True)
    rows = _build_investigation_rows(events, scans)
    ctl1, ctl2, ctl3, ctl4 = st.columns([1.25, 1.25, 1.25, 1.15], gap='medium')
    with ctl1:
        scan_query = st.text_input('Search by Scan ID', placeholder='Search by Scan ID', label_visibility='collapsed', key='all_inv_search_scan')
    with ctl2:
        ip_query = st.text_input('Search by Source IP', placeholder='Search by Source IP', label_visibility='collapsed', key='all_inv_search_ip')
    with ctl3:
        st.download_button('Download All Findings (CSV)', _all_findings_csv(rows), file_name='NetSentry_All_Investigations.csv', mime='text/csv', use_container_width=True, key='all_inv_download_csv')
    with ctl4:
        page_size = st.selectbox(
            'Records per page',
            [3, 6, 9, 12, 15],
            index=0,
            format_func=lambda x: f'Records per page: {x}',
            label_visibility='collapsed',
            key='all_investigations_page_size'
        )
    filtered = rows
    if scan_query.strip():
        filtered = [r for r in filtered if scan_query.strip().lower() in str(r['Scan ID']).lower()]
    if ip_query.strip():
        filtered = [r for r in filtered if ip_query.strip().lower() in str(r['Source IP']).lower()]
    total_pages = max(1, math.ceil(len(filtered) / page_size))
    page = min(st.session_state.get('all_investigations_page', 1), total_pages)
    columns = ['Scan ID', 'Timestamp', 'Source IP', 'Events', 'Unique Ports', 'Event IDs', 'Firewall Status', 'Details']
    head_html = ''.join((f'<th>{escape_html(col)}</th>' for col in columns))
    if not filtered:
        body_html = f"<tr class='ns-empty-row'><td colspan='{len(columns)}'>No investigation records match the current search.</td></tr>"
    else:
        page_rows = filtered[(page - 1) * page_size:page * page_size]
        body_html = ''.join(('<tr>' + ''.join((f"<td>{escape_html(row.get(col, '—'))}</td>" for col in columns)) + '</tr>' for row in page_rows))
    st.markdown(f'<div class="ns-investigations-table"><table><thead><tr>{head_html}</tr></thead><tbody>{body_html}</tbody></table></div>', unsafe_allow_html=True)
    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
    p1, p2, p3 = st.columns([1, 4, 1])
    with p1:
        if st.button('Previous Page', disabled=page <= 1, use_container_width=True, key='all_investigations_prev'):
            st.session_state['all_investigations_page'] = page - 1
            st.rerun()
    with p2:
        st.markdown(f"<div style='text-align:center;color:#94a3b8;padding:10px'>Page {page} of {total_pages}</div>", unsafe_allow_html=True)
    with p3:
        if st.button('Next Page', disabled=page >= total_pages, use_container_width=True, key='all_investigations_next'):
            st.session_state['all_investigations_page'] = page + 1
            st.rerun()
    st.markdown('<div class="ns-section-gap"></div>', unsafe_allow_html=True)
    st.markdown('### IP Block Management')
    st.markdown('<div class="ns-section-subtitle">Review firewall block records and manually remove an active block when required.</div>', unsafe_allow_html=True)
    active = monitoring_service.get_active_blocked_rules()
    all_rules = snap.get('firewall_rules', [])
    distinct_active = len({str(r.get('source_ip')) for r in active if r.get('source_ip')})
    total_unique_ips = len({str(e.get('source_ip')) for e in events if e.get('source_ip') not in (None, '', '-')})
    unblocked_count = len({str(r.get('source_ip')) for r in all_rules if str(r.get('status', '')).upper() in {'REMOVED', 'UNBLOCKED'} and r.get('source_ip')})
    render_kpi_row([{'label': 'Total Unique IPs', 'value': total_unique_ips, 'subtitle': 'Distinct observed source IPs', 'accent': '#60a5fa'}, {'label': 'Successfully Blocked IPs', 'value': distinct_active, 'subtitle': 'Currently active firewall blocks', 'accent': '#10b981'}, {'label': 'Unblocked IPs', 'value': unblocked_count, 'subtitle': 'Firewall rules removed', 'accent': '#22d3ee'}])
    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
    fw_columns = ['Source IP', 'Blocked At', 'Firewall Rule', 'Associated Scan ID', 'Status']
    fw_head_html = ''.join((f'<th>{escape_html(col)}</th>' for col in fw_columns))
    if all_rules:
        fw_body_html = ''.join((
            '<tr>' + ''.join((
                f"<td>{escape_html(val)}</td>" for val in [
                    rule.get('source_ip', '—'),
                    rule.get('created_at', '—'),
                    rule.get('rule_name', '—'),
                    rule.get('scan_id', '—'),
                    rule.get('status', '—')
                ]
            )) + '</tr>'
            for rule in all_rules
        ))
    else:
        fw_body_html = f"<tr class='ns-empty-row'><td colspan='{len(fw_columns)}'>No firewall block records are available.</td></tr>"
    st.markdown(f'<div class="ns-investigations-table"><table><thead><tr>{fw_head_html}</tr></thead><tbody>{fw_body_html}</tbody></table></div>', unsafe_allow_html=True)
    active_ips = sorted({str(r.get('source_ip')) for r in active if r.get('source_ip')})
    st.markdown("<div style='height:18px'></div>", unsafe_allow_html=True)
    c1, c2 = st.columns([3, 1], gap='medium')
    with c1:
        selected = st.selectbox('Select an IP to unblock', active_ips, index=None, placeholder='Select an IP to unblock', label_visibility='collapsed', key='dashboard_unblock_ip', disabled=not active_ips)
    with c2:
        if st.button('Manual Unblock', type='primary', use_container_width=True, key='dashboard_manual_unblock', disabled=not selected):
            result = monitoring_service.unblock_ip(selected)
            if getattr(result, 'status', '') == 'UNBLOCKED':
                st.success(f'{selected} was successfully unblocked.')
            else:
                st.error(getattr(result, 'message', f'Unable to unblock {selected}.'))
            st.rerun()
    if not active_ips:
        st.caption('There are no currently active blocked IP addresses to unblock.')

def render_investigation_details_page(history_service: HistoryService, report_service: ReportService, inline: bool=False) -> None:
    """Render the complete technical details view for a selected Scan ID."""
    scan_id = st.session_state.get('selected_scan_id')
    if not inline:
        top_c1, top_c2, top_c3 = st.columns([2.2, 5.4, 2.4])
        with top_c1:
            if st.button('Back to History', use_container_width=True, key='ns_back_to_history_btn'):
                st.session_state['selected_scan_id'] = None
                st.rerun()
        with top_c3:
            if scan_id:
                try:
                    pdf_bytes = report_service.generate_investigation_pdf_bytes(scan_id)
                    st.download_button(label='Download PDF', data=pdf_bytes, file_name=f'NetSentry_PortShield_{scan_id}.pdf', mime='application/pdf', type='primary', use_container_width=True, key='ns_detail_download_pdf_btn')
                except Exception as exc:
                    st.error(f'PDF export unavailable: {exc}')
    elif scan_id:
        try:
            pdf_bytes = report_service.generate_investigation_pdf_bytes(scan_id)
            st.download_button(label='Download PDF', data=pdf_bytes, file_name=f'NetSentry_PortShield_{scan_id}.pdf', mime='application/pdf', type='primary', use_container_width=True, key='ns_detail_inline_download_pdf_btn')
        except Exception as exc:
            st.error(f'PDF export unavailable: {exc}')
    if not scan_id:
        st.warning('No investigation Scan ID selected. Return to History to select an investigation.')
        return
    details = history_service.get_investigation_details(scan_id)
    if not details:
        st.error(f"Investigation record '{scan_id}' could not be found in SQLite.")
        return
    inv = details['investigation']
    events = details['events']
    rules = details['firewall_rules']
    unique_ips = details['unique_source_ips']
    st.markdown(f'<div class="ns-page-title">Investigation Details — <span class="ns-mono" style="color:#22d3ee;">{escape_html(scan_id)}</span></div><div class="ns-page-subtitle">Comprehensive telemetry, detection thresholds, firewall actions, and event timeline.</div>', unsafe_allow_html=True)
    render_kpi_row([{'label': 'Total Events', 'value': inv.get('total_events', 0), 'accent': '#38bdf8'}, {'label': 'Unique Source IPs', 'value': len(unique_ips), 'accent': '#22d3ee'}, {'label': 'Max Unique Ports', 'value': details['max_unique_ports'], 'accent': '#60a5fa'}, {'label': 'Successful Blocks', 'value': inv.get('successful_blocks', 0), 'accent': '#10b981'}])
    st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
    st.markdown('### Current Security Findings')
    if events:
        findings_columns = [
            'Event ID', 'Timestamp', 'Event', 'Source IP',
            'Unique Ports', 'Firewall Status', 'Details'
        ]
        head_html = ''.join((f'<th>{escape_html(col)}</th>' for col in findings_columns))
        body_rows = []
        for item in _group_consecutive_findings(events):
            row_values = [
                item['event_id_range'],
                item['timestamp'],
                item['event_type'],
                item['source_ip'],
                item['unique_ports'],
                item['firewall_status'],
                item['details'],
            ]
            cells_html = ''.join((f'<td>{escape_html(val)}</td>' for val in row_values))
            body_rows.append(f'<tr>{cells_html}</tr>')
        st.markdown(
            f'''
            <div class="ns-table-wrap">
                <table class="ns-table">
                    <thead><tr>{head_html}</tr></thead>
                    <tbody>{''.join(body_rows)}</tbody>
                </table>
            </div>
            ''',
            unsafe_allow_html=True,
        )
    else:
        st.info('No security findings have been recorded in this investigation.')
    st.markdown('### Report Metadata')
    try:
        elapsed_seconds = max(0.0, (datetime.fromisoformat(str(inv.get('end_time'))) - datetime.fromisoformat(str(inv.get('start_time')))).total_seconds()) if inv.get('end_time') and inv.get('start_time') else 0.0
    except ValueError:
        elapsed_seconds = 0.0
    st.markdown(f"""\n        <div class="ns-card">\n            <div class="ns-metadata-vertical">\n                <div><span>Scan ID</span><strong>{escape_html(inv.get('scan_id'))}</strong></div>\n                <div><span>Investigation Status</span><strong>{escape_html(inv.get('status'))}</strong></div>\n                <div><span>Start Time</span><strong>{escape_html(inv.get('start_time'))}</strong></div>\n                <div><span>End Time</span><strong>{escape_html(inv.get('end_time') or 'Active / Not ended')}</strong></div>\n                <div><span>Time Taken</span><strong>{elapsed_seconds:.2f} seconds</strong></div>\n                <div><span>Capture Interface</span><strong>{escape_html(inv.get('network_interface') or 'Not Recorded')}</strong></div>\n                <div><span>Detection Threshold &amp; Window</span><strong>{escape_html(inv.get('detection_threshold'))} unique TCP ports / {escape_html(inv.get('detection_window_seconds'))} seconds</strong></div>\n                <div><span>Observed Source IP Addresses</span><strong>{escape_html(', '.join(unique_ips) if unique_ips else 'None recorded')}</strong></div>\n            </div>\n        </div>\n        """, unsafe_allow_html=True)
    st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
    st.markdown('### Firewall Actions & Rule Details')
    if rules:
        fw_rows = []
        for r in rules:
            rem_info = r.get('removed_at') or r.get('failure_info') or '—'
            fw_rows.append(f"<tr><td class='ns-mono'>{escape_html(r.get('rule_name'))}</td><td class='ns-mono'>{escape_html(r.get('source_ip'))}</td><td>{escape_html(r.get('direction'))} / {escape_html(r.get('protocol'))} / {escape_html(r.get('action'))}</td><td>{status_badge_html(r.get('status', ''))}</td><td class='ns-mono'>{escape_html(r.get('created_at'))}</td><td>{escape_html(rem_info)}</td></tr>")
        st.markdown(f"""\n            <div class="ns-table-wrap">\n                <table class="ns-table">\n                    <thead>\n                        <tr>\n                            <th>Rule Name</th>\n                            <th>Source IP</th>\n                            <th>Direction / Protocol / Action</th>\n                            <th>Status</th>\n                            <th>Created At</th>\n                            <th>Removal / Failure Info</th>\n                        </tr>\n                    </thead>\n                    <tbody>{''.join(fw_rows)}</tbody>\n                </table>\n            </div>\n            """, unsafe_allow_html=True)
    else:
        st.markdown('<div class="ns-card" style="color:#94a3b8;">No firewall rules were created or modified during this investigation.</div>', unsafe_allow_html=True)
    st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
    st.markdown('### Investigation Timeline & Associated Detection Events')
    if events:
        ev_rows = []
        for ev in events:
            details_text = str(ev.get('detection_details') or '')
            match = re.search('Scanned destination ports:\\s*([0-9, ]+)', details_text, re.I)
            if not match:
                match = re.search('observed ports:\\s*([0-9, ]+)', details_text, re.I)
            ports_scanned = ', '.join(sorted(set(re.findall('\\d+', match.group(1))), key=int)) if match else '—'
            ev_rows.append(f"<tr><td class='ns-mono'>EVT-{int(ev.get('event_id') or 0):06d}</td><td class='ns-mono'>{escape_html(ev.get('timestamp'))}</td><td><strong>{escape_html(ev.get('event_type'))}</strong></td><td class='ns-mono'>{escape_html(ev.get('source_ip'))}</td><td class='ns-mono'>{escape_html(ev.get('unique_ports'))}</td><td class='ns-mono'>{escape_html(ports_scanned)}</td><td>{status_badge_html(ev.get('firewall_status', ''), ev.get('event_type', ''))}</td><td class='ns-mono'>{escape_html(ev.get('related_firewall_rule') or '—')}</td><td>{escape_html(ev.get('detection_details') or '—')}</td></tr>")
        st.markdown(f"""\n            <div class="ns-table-wrap">\n                <table class="ns-table">\n                    <thead>\n                        <tr>\n                            <th>Event ID</th>\n                            <th>Timestamp</th>\n                            <th>Event Type</th>\n                            <th>Source IP</th>\n                            <th>Unique Ports</th>\n                            <th>Ports Scanned</th>\n                            <th>Firewall Status</th>\n                            <th>Related Rule</th>\n                            <th>Details</th>\n                        </tr>\n                    </thead>\n                    <tbody>{''.join(ev_rows)}</tbody>\n                </table>\n            </div>\n            """, unsafe_allow_html=True)
    else:
        st.markdown('<div class="ns-card" style="color:#94a3b8;">No chronological events were recorded during this investigation.</div>', unsafe_allow_html=True)

st.set_page_config(page_title=f'{PROJECT_NAME} | {PRODUCT_NAME} ({APP_VERSION})', layout='wide', initial_sidebar_state='collapsed')

@st.cache_resource
def bootstrap_application():
    """Initialize SQLite, migrate legacy CSV safely, and wire singleton backend services."""
    db_manager = DatabaseManager(DB_PATH)
    initialize_database(db_manager)
    migrate_legacy_csv(db_manager, LEGACY_CSV_PATH)
    scan_repo = ScanRepository(db_manager)
    scan_repo.close_stale_running_investigations()
    event_repo = EventRepository(db_manager)
    firewall_manager = FirewallManager()
    engine = MonitoringEngine(scan_repo=scan_repo, event_repo=event_repo, firewall_manager=firewall_manager)
    atexit.register(engine.stop)
    monitoring_service = MonitoringService(engine, scan_repo, event_repo)
    history_service = HistoryService(scan_repo, event_repo)
    report_service = ReportService(scan_repo, event_repo)
    return (monitoring_service, history_service, report_service)

def init_session_state() -> None:
    if 'ns_notification' not in st.session_state:
        st.session_state['ns_notification'] = None
    if 'last_active_scan_id' not in st.session_state:
        st.session_state['last_active_scan_id'] = None
    if 'inspected_rule_id' not in st.session_state:
        st.session_state['inspected_rule_id'] = None

def main() -> None:
    inject_soc_theme()
    st.markdown('<style>\n    .ns-metadata-vertical{display:flex;flex-direction:column;gap:12px;padding:18px 20px;}\n    .ns-metadata-vertical>div{display:flex;flex-direction:column;gap:4px;padding-bottom:9px;border-bottom:1px solid #263b59;}\n    .ns-metadata-vertical>div:last-child{border-bottom:0;padding-bottom:0;}\n    .ns-metadata-vertical span{color:#7dd3fc;font-size:.72rem;text-transform:uppercase;font-weight:700;letter-spacing:.03em;}\n    .ns-metadata-vertical strong{color:#e2e8f0;font-size:.92rem;overflow-wrap:anywhere;}\n    .ns-progress-track{height:6px;background:rgba(34,211,238,.18);border-radius:8px;margin-top:10px;overflow:hidden;}\n    .ns-progress-bar{height:6px;width:38%;background:#22d3ee;border-radius:8px;animation:ns-progress 1.6s ease-in-out infinite alternate;}\n    @keyframes ns-progress{from{transform:translateX(0)}to{transform:translateX(155%)}}\n    .ns-section-heading{margin-top:1.2rem;margin-bottom:.6rem;}\n    [data-testid="stMarkdownContainer"] h3{margin-top:1.55rem !important;margin-bottom:.75rem !important;}\n    [data-testid="stVerticalBlock"] > [data-testid="stElementContainer"]{margin-bottom:.12rem;}\n    .ns-rule-panel{margin-top:16px !important;margin-bottom:22px !important;}\n    .ns-metadata-vertical{margin-bottom:0 !important;}\n    [data-testid="stSidebar"],[data-testid="collapsedControl"]{display:none !important;}\n    </style>', unsafe_allow_html=True)
    init_session_state()
    monitoring_service, history_service, report_service = bootstrap_application()
    render_header(is_monitoring_live=monitoring_service.is_running)
    render_investigate_page(monitoring_service, history_service, report_service)
    render_dashboard_page(monitoring_service, history_service, report_service)
    render_footer()

if __name__ == '__main__':
    main()
