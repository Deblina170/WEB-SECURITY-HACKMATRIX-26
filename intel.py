"""
Collaborative Threat Intelligence Module (intel.py)
Manages community threat reporting, crowd reputation voting,
known IOC (Indicators of Compromise) lookups, and global threat feed aggregation.
"""
import sqlite3
import json
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
from database import (
    get_db_connection,
    init_db,
    hybrid_query_iocs,
    hybrid_query_reports,
    hybrid_insert_report,
    hybrid_vote_report,
    hybrid_get_recent_feed
)

# Initialize database tables on import
init_db()

def normalize_domain_from_url(url_or_domain: str) -> str:
    """Normalizes URL or hostname into clean lowercase domain."""
    if "://" in url_or_domain:
        domain = urlparse(url_or_domain).hostname or url_or_domain
    else:
        domain = url_or_domain.split("/")[0]
    return domain.split(":")[0].lower().strip()


def lookup_threat_intel(url: str) -> Dict[str, Any]:
    """
    Looks up domain and URL against threat intelligence indicators
    and collaborative community reports in the hybrid database (Supabase / SQLite).
    """
    domain = normalize_domain_from_url(url)
    clean_url = url.strip()

    # Query hybrid database (Cloud Supabase if online, otherwise local SQLite)
    iocs = hybrid_query_iocs(domain, clean_url)
    reports = hybrid_query_reports(domain)

    # 3. Calculate Threat Intelligence Risk Score
    intel_risk_points = 0
    threat_verdict = "BENIGN"
    primary_threat_type = None

    if iocs:
        highest_conf_ioc = iocs[0]
        primary_threat_type = highest_conf_ioc["threat_type"]
        sev = highest_conf_ioc["severity"].lower()
        if sev == "critical":
            intel_risk_points = max(intel_risk_points, 90)
        elif sev == "high":
            intel_risk_points = max(intel_risk_points, 75)
        elif sev == "medium":
            intel_risk_points = max(intel_risk_points, 50)
        else:
            intel_risk_points = max(intel_risk_points, 30)

    # Factor in community reports and net consensus
    total_upvotes = sum(r["upvotes"] for r in reports)
    total_downvotes = sum(r["downvotes"] for r in reports)
    net_consensus = total_upvotes - total_downvotes

    if reports and net_consensus > 0:
        community_penalty = min(80, 30 + net_consensus * 2)
        intel_risk_points = max(intel_risk_points, community_penalty)
        if not primary_threat_type:
            primary_threat_type = reports[0]["category"]

    if intel_risk_points >= 80:
        threat_verdict = "CONFIRMED_MALICIOUS"
    elif intel_risk_points >= 40:
        threat_verdict = "SUSPICIOUS"
    else:
        threat_verdict = "CLEAN"

    reputation_score = max(0, 100 - intel_risk_points)

    return {
        "domain": domain,
        "threat_verdict": threat_verdict,
        "primary_threat_type": primary_threat_type,
        "intel_risk_points": intel_risk_points,
        "reputation_score": reputation_score,
        "matched_iocs_count": len(iocs),
        "iocs": iocs,
        "community_reports_count": len(reports),
        "reports": reports,
        "community_consensus": {
            "total_upvotes": total_upvotes,
            "total_downvotes": total_downvotes,
            "net_score": net_consensus,
            "reliability": "HIGH" if (total_upvotes + total_downvotes) >= 10 else "MODERATE" if reports else "NO_COMMUNITY_DATA"
        }
    }


def submit_community_report(
    target_url: str,
    category: str,
    description: str,
    reporter_name: str = "Anonymous Analyst",
    reporter_role: str = "community",
    impersonated_brand: Optional[str] = None,
    evidence_notes: Optional[str] = None
) -> Dict[str, Any]:
    """
    Submits a new collaborative threat intelligence report from users or analysts.
    Saves to hybrid database (Supabase + local SQLite).
    """
    domain = normalize_domain_from_url(target_url)

    report_id = hybrid_insert_report(
        target_url=target_url,
        domain=domain,
        category=category,
        description=description,
        reporter_name=reporter_name,
        reporter_role=reporter_role,
        impersonated_brand=impersonated_brand,
        evidence_notes=evidence_notes
    )

    return {
        "success": True,
        "report_id": report_id,
        "domain": domain,
        "message": f"Threat report #{report_id} successfully registered into collaborative intelligence network."
    }


def vote_on_report(report_id: int, voter_ip: str, vote_type: str) -> Dict[str, Any]:
    """
    Records an upvote or downvote for a community threat report.
    Prevents duplicate votes from the same IP address.
    """
    vote_type = vote_type.lower()
    if vote_type not in ["up", "down"]:
        return {"success": False, "message": "Invalid vote_type (must be 'up' or 'down')."}

    return hybrid_vote_report(report_id, voter_ip, vote_type)


def get_recent_threat_feed(limit: int = 15) -> List[Dict[str, Any]]:
    """
    Returns latest threat indicators and community reports for the feed dashboard.
    """
    return hybrid_get_recent_feed(limit)


def export_stix_2_1_bundle() -> Dict[str, Any]:
    """
    Exports threat intelligence indicators in standardized OASIS STIX 2.1 JSON format
    for direct ingestion into Enterprise SIEMs (Splunk, Microsoft Sentinel, MISP).
    """
    import uuid
    import datetime

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT indicator, indicator_type, threat_type, severity, confidence, description, first_seen, last_seen
        FROM threat_indicators
        WHERE is_active = 1
        ORDER BY confidence DESC
    """)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle_id = f"bundle--{uuid.uuid4()}"

    objects = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--4d32a901-b762-498c-8f12-threatguard-feed",
            "created": "2026-01-01T00:00:00Z",
            "modified": now,
            "name": "ThreatGuard Digital Trust Intelligence",
            "identity_class": "system",
            "sectors": ["cybersecurity", "financial-services", "trust-infrastructure"]
        }
    ]

    for r in rows:
        indicator_id = f"indicator--{uuid.uuid4()}"
        domain_val = r["indicator"]
        threat_type = r["threat_type"].lower()

        # Map threat type to STIX indicator type
        stix_types = ["malicious-activity"]
        if "phishing" in threat_type or "impersonation" in threat_type:
            stix_types.append("phishing")
        if "rogue" in threat_type or "cert" in threat_type:
            stix_types.append("anomalous-token")

        stix_indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": r.get("first_seen") or now,
            "modified": r.get("last_seen") or now,
            "pattern_type": "stix",
            "pattern": f"[domain-name:value = '{domain_val}']",
            "valid_from": r.get("first_seen") or now,
            "indicator_types": stix_types,
            "name": f"Malicious Indicator: {domain_val}",
            "description": r.get("description") or f"Detected {threat_type} activity targeting digital trust infrastructure.",
            "confidence": r.get("confidence", 85),
            "created_by_ref": "identity--4d32a901-b762-498c-8f12-threatguard-feed",
            "labels": [r["threat_type"], f"severity-{r['severity']}"]
        }
        objects.append(stix_indicator)

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects
    }
