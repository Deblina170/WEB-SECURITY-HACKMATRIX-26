"""
Hybrid Database Layer for Web Security Threat Detection & Digital Trust Intelligence.
Supports dual persistence:
1. Primary Cloud: Supabase (PostgreSQL) when credentials are provided.
2. Local/Offline: SQLite with automatic failover for air-gapped security environments.
"""
import sqlite3
import os
import json
import logging
import time
import socket
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_KEY = os.getenv("SUPABASE_KEY", os.getenv("SUPABASE_ANON_KEY", "")).strip()

_supabase_client = None
_supabase_init_attempted = False

# Dynamic network & air-gapped simulation state
AIR_GAPPED_OVERRIDE: Optional[bool] = None  # None = auto-detect, True = force offline, False = force online
_last_reachability_check: float = 0.0
_last_reachability_result: Tuple[bool, float, str] = (False, 0.0, "Unchecked")
REACHABILITY_CACHE_TTL = 3.0  # seconds

def check_supabase_reachability(force_refresh: bool = False) -> Tuple[bool, float, str]:
    """
    Tests live TCP connectivity to Supabase host.
    Returns (is_reachable, latency_ms, status_message).
    """
    global _last_reachability_check, _last_reachability_result

    # 1. Check manual simulation override
    if AIR_GAPPED_OVERRIDE is True:
        return False, 0.0, "Air-Gapped Simulation Active (Isolated Local SQLite)"

    if not SUPABASE_URL or not SUPABASE_KEY:
        return False, 0.0, "No Supabase credentials configured in environment"

    now = time.time()
    if not force_refresh and (now - _last_reachability_check < REACHABILITY_CACHE_TTL):
        return _last_reachability_result

    t0 = time.time()
    try:
        domain = urlparse(SUPABASE_URL).netloc
        if not domain:
            domain = SUPABASE_URL.replace("https://", "").replace("http://", "").split("/")[0]

        # Fast socket probe with 1.2s timeout
        s = socket.create_connection((domain, 443), timeout=1.2)
        s.close()
        latency_ms = round((time.time() - t0) * 1000, 2)
        _last_reachability_result = (True, latency_ms, f"Supabase Cloud reachable ({latency_ms}ms)")
    except Exception as e:
        latency_ms = round((time.time() - t0) * 1000, 2)
        _last_reachability_result = (False, latency_ms, f"Network unreachable: {e}")

    _last_reachability_check = now
    return _last_reachability_result

def is_supabase_online(force_refresh: bool = False) -> bool:
    """Returns True ONLY if Supabase is genuinely reachable right now."""
    reachable, _, _ = check_supabase_reachability(force_refresh=force_refresh)
    return reachable

def toggle_air_gapped_mode() -> bool:
    """Toggles manual air-gapped simulation override on/off."""
    global AIR_GAPPED_OVERRIDE, _last_reachability_check
    if AIR_GAPPED_OVERRIDE is True:
        AIR_GAPPED_OVERRIDE = False
    elif AIR_GAPPED_OVERRIDE is False:
        AIR_GAPPED_OVERRIDE = None
    else:
        AIR_GAPPED_OVERRIDE = True
    _last_reachability_check = 0.0
    return AIR_GAPPED_OVERRIDE is True

def set_air_gapped_mode(enabled: Optional[bool]):
    """Sets manual air-gapped simulation override."""
    global AIR_GAPPED_OVERRIDE, _last_reachability_check
    AIR_GAPPED_OVERRIDE = enabled
    _last_reachability_check = 0.0

def get_raw_supabase_client():
    """Lazily initializes the in-memory Supabase SDK client object."""
    global _supabase_client, _supabase_init_attempted
    if _supabase_init_attempted:
        return _supabase_client

    _supabase_init_attempted = True
    if SUPABASE_URL and SUPABASE_KEY:
        try:
            from supabase import create_client
            _supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
        except Exception as e:
            logging.warning(f"Could not construct Supabase client: {e}. Falling back to SQLite.")
            _supabase_client = None

    return _supabase_client

def get_supabase_client():
    """Returns Supabase client ONLY if Supabase is currently online and reachable."""
    if not is_supabase_online():
        return None
    return get_raw_supabase_client()

def get_active_db_info(force_refresh: bool = False) -> Dict[str, Any]:
    """Returns metadata about the active persistence engine and real network state."""
    is_online, latency_ms, reason = check_supabase_reachability(force_refresh=force_refresh)
    raw_client = get_raw_supabase_client()
    is_cloud_active = is_online and (raw_client is not None)

    return {
        "engine": "supabase" if is_cloud_active else "sqlite",
        "provider": "Supabase (Cloud PostgreSQL)" if is_cloud_active else "SQLite (Local / Air-Gapped)",
        "is_hybrid": True,
        "is_cloud_active": is_cloud_active,
        "fallback_engine": "SQLite 3",
        "database_file": "threat_intel.db",
        "network_status": "online" if is_online else "offline",
        "air_gapped_mode": not is_cloud_active,
        "air_gap_override": AIR_GAPPED_OVERRIDE,
        "latency_ms": latency_ms,
        "status_reason": reason
    }

# ---------------------------------------------------------------------------
# SQLite Engine (Local Baseline & Offline Failover)
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threat_intel.db")

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes local SQLite schema and seeds baseline intelligence."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Threat Indicators table (IOCs)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT UNIQUE NOT NULL,      -- domain, url, or hash
        indicator_type TEXT NOT NULL,       -- domain, url, ip, cert_fingerprint
        threat_type TEXT NOT NULL,          -- phishing, malware, scam, impersonation, rogue_ca
        severity TEXT NOT NULL,             -- critical, high, medium, low
        confidence INTEGER DEFAULT 80,      -- 0 to 100
        source TEXT NOT NULL,               -- feed, community, analyst, incident_bulletin
        description TEXT,
        metadata TEXT,                      -- JSON details
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active INTEGER DEFAULT 1
    );
    """)

    # 2. Collaborative Community Reports table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS community_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_url TEXT NOT NULL,
        domain TEXT NOT NULL,
        reporter_name TEXT DEFAULT 'Anonymous Analyst',
        reporter_role TEXT DEFAULT 'community', -- community, analyst, cert_auditor
        category TEXT NOT NULL,                -- phishing, fake_recruitment, rogue_cert, scam
        description TEXT NOT NULL,
        impersonated_brand TEXT,
        evidence_notes TEXT,
        upvotes INTEGER DEFAULT 1,
        downvotes INTEGER DEFAULT 0,
        status TEXT DEFAULT 'verified',        -- pending, verified, rejected
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 3. Community Votes table (prevent duplicate votes)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS community_votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id INTEGER NOT NULL,
        voter_ip TEXT NOT NULL,
        vote_type TEXT NOT NULL,               -- up, down
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(report_id, voter_ip)
    );
    """)

    # 4. Scan History table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        domain TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        trust_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        summary TEXT,
        scan_result TEXT,                      -- full JSON result
        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()

    # Seed baseline threat data if empty
    cursor.execute("SELECT COUNT(*) FROM threat_indicators")
    count = cursor.fetchone()[0]
    if count == 0:
        seed_threat_data(cursor)
        conn.commit()

    conn.close()

def seed_threat_data(cursor: sqlite3.Cursor):
    """Seed initial known threat indicators and community reports."""
    seed_iocs = [
        (
            "paypa1-security-verification.update-account.tk",
            "domain",
            "phishing",
            "critical",
            98,
            "incident_bulletin",
            "Active credential harvesting attack impersonating PayPal billing verification.",
            json.dumps({"target_brand": "PayPal", "technique": "homograph_typosquatting", "ports": [80, 443]})
        ),
        (
            "chase-online-login-verify.support-portal.info",
            "domain",
            "phishing",
            "critical",
            95,
            "feed",
            "Targeted Chase Bank account takeover credential harvesting form.",
            json.dumps({"target_brand": "Chase Bank", "technique": "brand_spoofing"})
        ),
        (
            "amazon-global-careers-recruit.xyz",
            "domain",
            "fake_recruitment",
            "high",
            90,
            "community",
            "Fake recruitment portal offering remote positions and harvesting identity documents and advance fees.",
            json.dumps({"target_brand": "Amazon", "technique": "recruitment_scam"})
        ),
        (
            "emudhra-auth-portal.fraud-verify.com",
            "domain",
            "rogue_ca",
            "critical",
            99,
            "incident_bulletin",
            "Impersonation of eMudhra Trust Services with rogue intermediate certificate signature.",
            json.dumps({"target_brand": "eMudhra", "technique": "ca_impersonation_weak_key"})
        ),
        (
            "microsoft-365-password-reset.live-security.online",
            "domain",
            "phishing",
            "critical",
            96,
            "analyst",
            "Office 365 OAuth & password harvesting reverse proxy.",
            json.dumps({"target_brand": "Microsoft", "technique": "mfa_bypass_proxy"})
        ),
        (
            "binance-kyc-reactivation.secure-crypto-wallet.cc",
            "domain",
            "scam",
            "critical",
            97,
            "community",
            "Cryptocurrency wallet seed-phrase harvesting site targeting Binance users.",
            json.dumps({"target_brand": "Binance", "technique": "seed_phrase_theft"})
        )
    ]

    for item in seed_iocs:
        cursor.execute("""
            INSERT OR IGNORE INTO threat_indicators
            (indicator, indicator_type, threat_type, severity, confidence, source, description, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, item)

    # Seed community reports
    seed_reports = [
        (
            "http://paypa1-security-verification.update-account.tk/login",
            "paypa1-security-verification.update-account.tk",
            "CyberSecAnalyst_99",
            "analyst",
            "phishing",
            "Phishing site using deceptive homograph paypa1 with digit '1'. Contains exact clone of PayPal login and asks for full credit card CVV.",
            "PayPal",
            "Form posts unencrypted creds to external Russia-based IP.",
            42,
            1,
            "verified"
        ),
        (
            "http://amazon-global-careers-recruit.xyz/apply",
            "amazon-global-careers-recruit.xyz",
            "RecruitmentDefense",
            "community",
            "fake_recruitment",
            "Victims report receiving unsolicited WhatsApp job offers linking to this portal. Site asks for $150 background verification fee.",
            "Amazon",
            "Scam recruiter emails originating from spoofed domain.",
            28,
            0,
            "verified"
        ),
        (
            "https://emudhra-auth-portal.fraud-verify.com",
            "emudhra-auth-portal.fraud-verify.com",
            "CertAuditTeam",
            "cert_auditor",
            "rogue_cert",
            "Simulated incident: Certificate uses an unauthorized intermediate mimicking eMudhra CA with a 1024-bit weak key and missing Certificate Transparency SCT.",
            "eMudhra",
            "Failed public CT log validation and revoked serial range.",
            56,
            2,
            "verified"
        )
    ]

    for report in seed_reports:
        cursor.execute("""
            INSERT INTO community_reports
            (target_url, domain, reporter_name, reporter_role, category, description, impersonated_brand, evidence_notes, upvotes, downvotes, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, report)

# ---------------------------------------------------------------------------
# Unified Hybrid Query Operations (Supabase -> SQLite Fallback)
# ---------------------------------------------------------------------------

def hybrid_query_iocs(domain: str, clean_url: str) -> List[Dict[str, Any]]:
    """Queries IOCs from Supabase if online, falling back to local SQLite."""
    sb = get_supabase_client()
    if sb:
        try:
            # Query Supabase PostgreSQL
            res = sb.table("threat_indicators").select("*").eq("is_active", 1).or_(
                f"indicator.eq.{domain},indicator.eq.{clean_url},indicator.ilike.%{domain}%"
            ).order("confidence", desc=True).execute()
            if res.data:
                return res.data
        except Exception as e:
            logging.info(f"Supabase IOC query fell back to SQLite: {e}")

    # Local SQLite fallback
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT indicator, indicator_type, threat_type, severity, confidence, source, description, metadata, first_seen
        FROM threat_indicators
        WHERE is_active = 1 AND (
            indicator = ? OR indicator = ? OR ? LIKE '%' || indicator || '%'
        )
        ORDER BY confidence DESC
    """, (clean_url, domain, domain))
    iocs = [dict(row) for row in cursor.fetchall()]
    conn.close()

    for ioc in iocs:
        if ioc.get("metadata") and isinstance(ioc["metadata"], str):
            try:
                ioc["metadata"] = json.loads(ioc["metadata"])
            except Exception:
                pass
    return iocs

def hybrid_query_reports(domain: str) -> List[Dict[str, Any]]:
    """Queries community reports from Supabase if online, falling back to local SQLite."""
    sb = get_supabase_client()
    if sb:
        try:
            res = sb.table("community_reports").select("*").or_(
                f"domain.eq.{domain},domain.ilike.%{domain}%"
            ).order("upvotes", desc=True).execute()
            if res.data:
                return res.data
        except Exception as e:
            logging.info(f"Supabase reports query fell back to SQLite: {e}")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, target_url, domain, reporter_name, reporter_role, category,
               description, impersonated_brand, evidence_notes, upvotes, downvotes, status, created_at
        FROM community_reports
        WHERE domain = ? OR ? LIKE '%' || domain || '%'
        ORDER BY (upvotes - downvotes) DESC, created_at DESC
    """, (domain, domain))
    reports = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return reports

def hybrid_insert_report(
    target_url: str,
    domain: str,
    category: str,
    description: str,
    reporter_name: str,
    reporter_role: str,
    impersonated_brand: Optional[str],
    evidence_notes: Optional[str]
) -> int:
    """Inserts report into SQLite, and syncs to Supabase if configured."""
    # 1. Local SQLite write
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO community_reports
        (target_url, domain, reporter_name, reporter_role, category, description, impersonated_brand, evidence_notes, upvotes, downvotes, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 'verified')
    """, (target_url, domain, reporter_name, reporter_role, category, description, impersonated_brand, evidence_notes))
    report_id = cursor.lastrowid

    # Auto insert/update IOC in local SQLite
    cursor.execute("""
        INSERT INTO threat_indicators
        (indicator, indicator_type, threat_type, severity, confidence, source, description, metadata)
        VALUES (?, 'domain', ?, 'high', 85, 'community', ?, ?)
        ON CONFLICT(indicator) DO UPDATE SET
            last_seen = CURRENT_TIMESTAMP,
            confidence = MIN(100, confidence + 5)
    """, (
        domain,
        category,
        description,
        json.dumps({"reported_by": reporter_name, "role": reporter_role, "brand": impersonated_brand})
    ))
    conn.commit()
    conn.close()

    # 2. Cloud Supabase Sync
    sb = get_supabase_client()
    if sb:
        try:
            sb.table("community_reports").insert({
                "target_url": target_url,
                "domain": domain,
                "reporter_name": reporter_name,
                "reporter_role": reporter_role,
                "category": category,
                "description": description,
                "impersonated_brand": impersonated_brand,
                "evidence_notes": evidence_notes,
                "upvotes": 1,
                "downvotes": 0,
                "status": "verified"
            }).execute()
        except Exception as e:
            logging.warning(f"Could not sync report to Supabase: {e}")

    return report_id

def hybrid_vote_report(report_id: int, voter_ip: str, vote_type: str) -> Dict[str, Any]:
    """Records an upvote or downvote with duplicate voter check."""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id FROM community_votes WHERE report_id = ? AND voter_ip = ?", (report_id, voter_ip))
        existing = cursor.fetchone()
        if existing:
            conn.close()
            return {"success": False, "message": "You have already voted on this threat report."}

        cursor.execute("INSERT INTO community_votes (report_id, voter_ip, vote_type) VALUES (?, ?, ?)", (report_id, voter_ip, vote_type))
        if vote_type == "up":
            cursor.execute("UPDATE community_reports SET upvotes = upvotes + 1 WHERE id = ?", (report_id,))
        else:
            cursor.execute("UPDATE community_reports SET downvotes = downvotes + 1 WHERE id = ?", (report_id,))

        conn.commit()

        cursor.execute("SELECT upvotes, downvotes FROM community_reports WHERE id = ?", (report_id,))
        row = cursor.fetchone()
        upvotes = row[0] if row else 0
        downvotes = row[1] if row else 0
        conn.close()

        # Sync vote to Supabase if active
        sb = get_supabase_client()
        if sb:
            try:
                sb.table("community_reports").update({
                    "upvotes": upvotes,
                    "downvotes": downvotes
                }).eq("id", report_id).execute()
            except Exception:
                pass

        return {
            "success": True,
            "report_id": report_id,
            "upvotes": upvotes,
            "downvotes": downvotes,
            "net_score": upvotes - downvotes
        }
    except Exception as e:
        conn.close()
        return {"success": False, "error": str(e)}

def hybrid_get_recent_feed(limit: int = 15) -> List[Dict[str, Any]]:
    """Gets latest threat indicators from Supabase or SQLite."""
    sb = get_supabase_client()
    if sb:
        try:
            res = sb.table("threat_indicators").select("*").eq("is_active", 1).order("last_seen", desc=True).limit(limit).execute()
            if res.data:
                return res.data
        except Exception:
            pass

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT indicator, indicator_type, threat_type, severity, confidence, source, description, first_seen, last_seen
        FROM threat_indicators
        WHERE is_active = 1
        ORDER BY last_seen DESC
        LIMIT ?
    """, (limit,))
    iocs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return iocs

def hybrid_save_scan(target_url: str, domain: str, risk_score: int, trust_score: int, risk_level: str, summary: str, full_json: str):
    """
    Saves scan telemetry with preference for cloud Supabase when online,
    and automatically registers detected threats (CRITICAL / HIGH) into Supabase IOC feed.
    Always mirrors to local SQLite for air-gapped continuity.
    """
    # 1. Cloud Supabase Preference (When online)
    sb = get_supabase_client()
    if sb:
        try:
            parsed_json = {}
            if isinstance(full_json, str):
                try:
                    parsed_json = json.loads(full_json)
                except Exception:
                    pass
            elif isinstance(full_json, dict):
                parsed_json = full_json

            # 1a. Save audit telemetry to cloud Supabase
            try:
                sb.table("scan_history").insert({
                    "url": target_url,
                    "domain": domain,
                    "risk_score": risk_score,
                    "trust_score": trust_score,
                    "risk_level": risk_level,
                    "summary": summary,
                    "scan_result": parsed_json
                }).execute()
            except Exception:
                pass

            # 1b. Autonomous Threat Propagation: If high risk or phishing detected, publish to Supabase IOCs!
            if risk_level in ["CRITICAL", "HIGH"] or risk_score >= 70:
                try:
                    threat_type = "phishing" if risk_score >= 80 else "suspicious_domain"
                    severity = "critical" if risk_score >= 85 else "high"
                    sb.table("threat_indicators").upsert({
                        "indicator": domain,
                        "indicator_type": "domain",
                        "threat_type": threat_type,
                        "severity": severity,
                        "confidence": min(98, max(75, risk_score)),
                        "source": "ThreatGuard AI Autonomous Detection",
                        "description": summary[:250] if summary else f"Automated detection: {risk_level} risk ({risk_score}/100)",
                        "metadata": {"auto_detected": True, "target_url": target_url, "risk_score": risk_score}
                    }, on_conflict="indicator").execute()
                except Exception:
                    pass
        except Exception:
            pass

    # 2. Local SQLite Mirror / Fallback
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_history
            (url, domain, risk_score, trust_score, risk_level, summary, scan_result)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (target_url, domain, risk_score, trust_score, risk_level, summary, full_json))

        # Mirror auto-detected threat into local SQLite IOC table
        if risk_level in ["CRITICAL", "HIGH"] or risk_score >= 70:
            threat_type = "phishing" if risk_score >= 80 else "suspicious_domain"
            severity = "critical" if risk_score >= 85 else "high"
            cursor.execute("""
                INSERT INTO threat_indicators
                (indicator, indicator_type, threat_type, severity, confidence, source, description, metadata)
                VALUES (?, 'domain', ?, ?, ?, 'ThreatGuard AI Autonomous Detection', ?, ?)
                ON CONFLICT(indicator) DO UPDATE SET
                    last_seen = CURRENT_TIMESTAMP,
                    confidence = MAX(confidence, excluded.confidence)
            """, (
                domain,
                threat_type,
                severity,
                min(98, max(75, risk_score)),
                summary[:250] if summary else f"Automated detection: {risk_level} risk",
                json.dumps({"auto_detected": True, "target_url": target_url, "risk_score": risk_score})
            ))

        conn.commit()
        conn.close()
    except Exception:
        pass
