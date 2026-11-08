"""
FastAPI Application (main.py)
Core threat detection, web security scanning, certificate validation,
and collaborative intelligence API.
"""
import os
import json
import uuid
import datetime
from urllib.parse import urlparse
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel, Field

import database
import threat
import webscan
import certs
import intel
import risk

app = FastAPI(
    title="AI-Powered Web Threat Detection & Digital Trust Intelligence",
    description="Combines phishing threat heuristics, web security assessment, cryptographic certificate validation, and collaborative threat intelligence.",
    version="2.0.0"
)

# Enable CORS for frontend and external clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
database.init_db()

# Models for request validation
class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="Target URL or domain to analyze")

class ReportSubmissionRequest(BaseModel):
    target_url: str
    category: str = Field(..., description="phishing, fake_recruitment, rogue_cert, scam")
    description: str
    reporter_name: Optional[str] = "Anonymous Analyst"
    reporter_role: Optional[str] = "community"
    impersonated_brand: Optional[str] = None
    evidence_notes: Optional[str] = None

class VoteRequest(BaseModel):
    report_id: int
    vote_type: str = Field(..., description="'up' or 'down'")


def perform_analysis(url_input: str) -> Dict[str, Any]:
    """
    Core Analysis Engine:
    Executes simultaneous multi-vector security assessment across:
    - threat.py: AI phishing, homographs, typosquatting, credential harvesting
    - certs.py: X.509 cryptography, CA validation, eMudhra incident audit
    - webscan.py: Security headers, cookie flags, mixed content, server leaks
    - intel.py: Collaborative threat indicators, community reports, reputation
    - risk.py: Composite risk calculation, digital trust score, and explainable AI verdict
    """
    if not url_input or not url_input.strip():
        raise HTTPException(
            status_code=400,
            detail="Missing required 'url' parameter. Example: /analyze?url=https://chase.com"
        )

    target_url = url_input.strip()
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    parsed = urlparse(target_url)
    domain = parsed.hostname or target_url
    if ":" in domain:
        domain = domain.split(":")[0]

    scan_id = str(uuid.uuid4())
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # 1. Threat Heuristics Analysis
    threat_result = threat.analyze_threat(target_url)

    # 2. Web Security Posture Scan
    web_result = webscan.scan_web_security(target_url)

    # 3. Certificate & Digital Trust Analysis (including eMudhra checks)
    certs_result = certs.validate_certificate(target_url)

    # 4. Collaborative Threat Intelligence & Community Lookup
    intel_result = intel.lookup_threat_intel(target_url)

    # 5. Composite Risk & Explainable AI Aggregation
    composite_risk = risk.calculate_composite_risk(
        threat_data=threat_result,
        cert_data=certs_result,
        web_data=web_result,
        intel_data=intel_result
    )

    full_response = {
        "status": "success",
        "scan_id": scan_id,
        "scanned_at": timestamp,
        "target_url": target_url,
        "domain": domain,
        "verdict": {
            "risk_level": composite_risk["risk_level"],
            "risk_score": composite_risk["composite_risk_score"],
            "trust_score": composite_risk["digital_trust_score"],
            "badge_color": composite_risk["badge_color"],
            "summary": composite_risk["summary_verdict"],
            "threat_factors": composite_risk["threat_factors"],
            "breakdown": composite_risk["breakdown"]
        },
        "threat_analysis": threat_result,
        "certificate_analysis": certs_result,
        "web_security": web_result,
        "threat_intelligence": intel_result,
        "recommendations": {
            "user_guidance": composite_risk["user_guidance"],
            "admin_remediation": composite_risk["admin_remediation"]
        }
    }

    # Store in scan history table
    database.hybrid_save_scan(
        target_url=target_url,
        domain=domain,
        risk_score=composite_risk["composite_risk_score"],
        trust_score=composite_risk["digital_trust_score"],
        risk_level=composite_risk["risk_level"],
        summary=composite_risk["summary_verdict"],
        full_json=json.dumps(full_response)
    )

    return full_response


# ---------------------------------------------------------------------------
# CORE ENDPOINT: /analyze?url=...
# ---------------------------------------------------------------------------
@app.get("/analyze", summary="Core URL Threat & Digital Trust Analyzer")
def analyze_url_get(url: Optional[str] = Query(None, description="Target URL or domain to analyze")):
    if not url:
        raise HTTPException(
            status_code=400,
            detail="Missing required 'url' query parameter. Example: /analyze?url=https://chase.com"
        )
    return perform_analysis(url)

@app.post("/analyze", summary="Core URL Threat & Digital Trust Analyzer (POST)")
def analyze_url_post(body: AnalyzeRequest):
    return perform_analysis(body.url)

# Alias /api/analyze for REST clients
@app.get("/api/analyze")
def api_analyze_get(url: Optional[str] = Query(None)):
    if not url:
        raise HTTPException(status_code=400, detail="Missing required 'url' query parameter.")
    return perform_analysis(url)

@app.post("/api/analyze")
def api_analyze_post(body: AnalyzeRequest):
    return perform_analysis(body.url)


# ---------------------------------------------------------------------------
# Collaborative Intelligence Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/intel/report", summary="Submit a Collaborative Threat Report")
def report_threat_endpoint(report: ReportSubmissionRequest):
    """Allows users, researchers, or analysts to report malicious websites."""
    res = intel.submit_community_report(
        target_url=report.target_url,
        category=report.category,
        description=report.description,
        reporter_name=report.reporter_name,
        reporter_role=report.reporter_role,
        impersonated_brand=report.impersonated_brand,
        evidence_notes=report.evidence_notes
    )
    return res

@app.post("/api/intel/vote", summary="Vote on a Community Threat Report")
def vote_threat_endpoint(vote: VoteRequest, request: Request):
    """Records an upvote or downvote to build crowd consensus."""
    voter_ip = request.client.host if request.client else "127.0.0.1"
    res = intel.vote_on_report(
        report_id=vote.report_id,
        voter_ip=voter_ip,
        vote_type=vote.vote_type
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("message", "Vote failed"))
    return res

@app.get("/api/threats/feed", summary="Get Live Threat Intelligence IOC Feed")
def get_threat_feed_endpoint(limit: int = 20):
    """Returns the latest threat indicators from the collaborative intelligence database."""
    return {"feed": intel.get_recent_threat_feed(limit)}

@app.get("/api/threats/stix", summary="Export Standardized STIX 2.1 Threat Intelligence Bundle")
def export_stix_endpoint():
    """
    Exports all active Indicators of Compromise (IOCs) formatted according to
    OASIS STIX 2.1 international cyber threat intelligence specifications
    for enterprise SIEM / SOAR integrations (Splunk, Sentinel, MISP).
    """
    return intel.export_stix_2_1_bundle()

@app.get("/api/history", summary="Get Scan History")
def get_scan_history_endpoint(limit: int = 10):
    """Returns recent analysis scans."""
    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, url, domain, risk_score, trust_score, risk_level, summary, scanned_at
        FROM scan_history
        ORDER BY scanned_at DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"history": rows}

@app.get("/api/samples", summary="Get Curated Demonstration Scenarios")
def get_samples_endpoint():
    """Provides preset test cases demonstrating different threat vectors."""
    samples = [
        {
            "title": "PayPal Credential Phishing",
            "url": "http://paypa1-security-verification.update-account.tk/login",
            "category": "Homograph & Credential Harvester",
            "expected_verdict": "CRITICAL",
            "description": "Homograph typosquatting domain (paypa1 with '1') on suspicious .tk TLD harvesting account credentials."
        },
        {
            "title": "eMudhra TLS Weak Key Simulation",
            "url": "https://emudhra-auth-portal.fraud-verify.com",
            "category": "CA Incident & Weak Crypto Key",
            "expected_verdict": "CRITICAL",
            "description": "Demonstrates the eMudhra TLS Certificate incident: 1024-bit weak RSA key, missing CT logging, and fraudulent intermediate."
        },
        {
            "title": "Amazon Recruitment Scam",
            "url": "http://amazon-global-careers-recruit.xyz/apply",
            "category": "Fake Recruitment Fraud",
            "expected_verdict": "HIGH",
            "description": "Deceptive employment lure portal harvesting applicant identity documents and advance processing fees."
        },
        {
            "title": "Chase Online Banking (Legitimate)",
            "url": "https://chase.com",
            "category": "Trusted Corporate Portal",
            "expected_verdict": "CLEAN",
            "description": "Authentic enterprise banking site with verified Root CA, 2048-bit RSA, strict HSTS, and valid CT logging."
        },
        {
            "title": "Legacy Unencrypted Portal",
            "url": "http://legacy-banking.insecure.test",
            "category": "Missing Encryption & Headers",
            "expected_verdict": "HIGH",
            "description": "Unencrypted HTTP transport, leaking server banners, and zero browser security headers."
        }
    ]
    return {"samples": samples}

@app.get("/health", summary="Health Check")
@app.head("/health", summary="Health Check")
def health_check():
    return {
        "status": "healthy",
        "system": "AI-Powered Web Threat Detection & Digital Trust Intelligence",
        "database": database.get_active_db_info(),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

@app.get("/api/system/db-status", summary="Get Active Database Engine & Persistence Mode")
def get_db_status_endpoint(force_refresh: bool = False):
    """Returns whether running on Supabase (Cloud PostgreSQL) or SQLite (Local Failover)."""
    return database.get_active_db_info(force_refresh=force_refresh)

@app.post("/api/system/toggle-airgap", summary="Toggle Air-Gapped Simulation Mode")
@app.get("/api/system/toggle-airgap", summary="Toggle Air-Gapped Simulation Mode")
def toggle_airgap_endpoint():
    """Toggles air-gapped demo mode (forces local SQLite failover on or off for presentations)."""
    database.toggle_air_gapped_mode()
    return database.get_active_db_info(force_refresh=True)


# ---------------------------------------------------------------------------
# Static Web Dashboard Frontend Mount
# ---------------------------------------------------------------------------
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/", response_class=HTMLResponse, summary="ThreatGuard Web Dashboard")
@app.head("/", summary="ThreatGuard Web Dashboard Head Check")
def serve_index():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>Web Threat Detection API is running. Access /analyze?url=... or /docs</h1>")
