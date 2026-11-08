"""
Automated Test Suite for Web Security Threat Detection API (test_api.py)
Tests all API endpoints, /analyze query and body handlers, individual modules,
threat heuristics, cryptographic certificate validation, and eMudhra incident checks.
"""
import sys
import json
from pydantic import ValidationError

import main
from main import (
    perform_analysis,
    analyze_url_get,
    analyze_url_post,
    api_analyze_get,
    api_analyze_post,
    health_check,
    report_threat_endpoint,
    vote_threat_endpoint,
    get_threat_feed_endpoint,
    get_samples_endpoint,
    get_scan_history_endpoint,
    AnalyzeRequest,
    ReportSubmissionRequest,
    VoteRequest
)
import threat
import webscan
import certs
import intel
import risk

def test_health():
    data = health_check()
    assert data["status"] == "healthy"
    print("[PASS] Health endpoint test passed.")

def test_missing_url():
    try:
        analyze_url_get(url=None)
        assert False, "Should have raised HTTPException for missing URL"
    except Exception as e:
        assert getattr(e, "status_code", None) == 400
        print("[PASS] Missing URL raises HTTP 400 correctly.")

def test_analyze_paypal_phishing():
    url = "http://paypa1-security-verification.update-account.tk/login"
    data = analyze_url_get(url=url)
    
    assert data["status"] == "success"
    assert "paypa1" in data["domain"]
    verdict = data["verdict"]
    assert verdict["risk_level"] in ["CRITICAL", "HIGH"]
    assert verdict["risk_score"] >= 80
    assert verdict["trust_score"] <= 20
    
    threat_res = data["threat_analysis"]
    assert threat_res["is_phishing"] is True
    assert threat_res["impersonated_brand"] == "Paypal"
    
    intel_res = data["threat_intelligence"]
    assert intel_res["matched_iocs_count"] >= 1
    print(f"[PASS] Phishing detection test passed: Risk={verdict['risk_score']}, Trust={verdict['trust_score']}, Brand={threat_res['impersonated_brand']}")

def test_analyze_emudhra_incident():
    url = "https://emudhra-auth-portal.fraud-verify.com"
    data = analyze_url_get(url=url)
    
    verdict = data["verdict"]
    assert verdict["risk_level"] == "CRITICAL"
    
    cert_res = data["certificate_analysis"]
    emudhra_analysis = cert_res["emudhra_incident_analysis"]
    assert emudhra_analysis["is_emudhra_ca"] is True or emudhra_analysis["advisory_status"] != "NORMAL"
    assert cert_res["cryptography"]["key_size_bits"] == 1024
    assert cert_res["trust_chain"]["has_certificate_transparency_sct"] is False
    print(f"[PASS] eMudhra TLS Incident test passed: Key={cert_res['cryptography']['key_size_bits']} bits, Advisory={emudhra_analysis['advisory_status']}")

def test_analyze_legitimate_chase():
    url = "https://chase.com"
    data = analyze_url_get(url=url)
    
    verdict = data["verdict"]
    assert verdict["risk_level"] in ["CLEAN", "LOW"]
    assert verdict["trust_score"] >= 80
    assert data["threat_analysis"]["is_phishing"] is False
    print(f"[PASS] Legitimate domain test passed: Risk Level={verdict['risk_level']}, Trust={verdict['trust_score']}")

def test_post_analyze():
    req = AnalyzeRequest(url="https://chase.com")
    data = analyze_url_post(body=req)
    assert data["domain"] == "chase.com"
    assert data["status"] == "success"
    print("[PASS] POST /analyze test passed.")

def test_community_reporting_and_voting():
    report_payload = ReportSubmissionRequest(
        target_url="http://fake-crypto-wallet-bonus.claim-token.xyz",
        category="scam",
        description="Scam crypto site claiming free Ethereum airdrop, drains metamask wallet.",
        reporter_name="TestAnalyst",
        reporter_role="analyst",
        impersonated_brand="Ethereum",
        evidence_notes="Contract address drains all ERC-20 allowances."
    )
    
    rep_data = report_threat_endpoint(report_payload)
    assert rep_data["success"] is True
    report_id = rep_data["report_id"]

    # Vote on report via mock request
    class MockClient:
        host = "192.168.1.105"
    class MockRequest:
        client = MockClient()

    vote_payload = VoteRequest(report_id=report_id, vote_type="up")
    vote_data = vote_threat_endpoint(vote=vote_payload, request=MockRequest())
    assert vote_data["success"] is True
    assert vote_data["upvotes"] >= 2
    print(f"[PASS] Community reporting and voting test passed: Report ID #{report_id}")

def test_threat_feed_and_samples():
    feed_data = get_threat_feed_endpoint(limit=10)
    assert len(feed_data["feed"]) > 0

    samples_data = get_samples_endpoint()
    assert len(samples_data["samples"]) >= 4

    history_data = get_scan_history_endpoint(limit=5)
    assert "history" in history_data
    print(f"[PASS] Feed, Samples, and History endpoints passed (History entries: {len(history_data['history'])})")

def test_stix_export():
    from main import export_stix_endpoint
    stix_bundle = export_stix_endpoint()
    assert stix_bundle["type"] == "bundle"
    assert stix_bundle["spec_version"] == "2.1"
    assert len(stix_bundle["objects"]) >= 2
    assert any(obj["type"] == "identity" for obj in stix_bundle["objects"])
    assert any(obj["type"] == "indicator" for obj in stix_bundle["objects"])
    print(f"[PASS] STIX 2.1 Threat Intelligence export passed ({len(stix_bundle['objects'])} STIX objects).")

def test_dual_persistence_and_airgap():
    import database
    from main import get_db_status_endpoint, toggle_airgap_endpoint

    # 1. Test real-time status inspection
    status = get_db_status_endpoint(force_refresh=True)
    assert "engine" in status
    assert "is_cloud_active" in status
    assert "fallback_engine" in status

    # 2. Test air-gapped simulation toggle
    toggled = toggle_airgap_endpoint()
    assert toggled["air_gap_override"] is True
    assert toggled["engine"] == "sqlite"
    assert toggled["is_cloud_active"] is False

    # 3. Reset
    database.set_air_gapped_mode(None)
    reset = get_db_status_endpoint(force_refresh=True)
    assert reset["air_gap_override"] is None
    print(f"[PASS] Dual Persistence & Dynamic Air-Gapped Failover verified (Engine: {reset['engine']}, Cloud Active: {reset['is_cloud_active']}).")

if __name__ == "__main__":
    print("==================================================")
    print("RUNNING WEB THREAT INTELLIGENCE SYSTEM TEST SUITE")
    print("==================================================")
    test_health()
    test_missing_url()
    test_dual_persistence_and_airgap()
    test_analyze_paypal_phishing()
    test_analyze_emudhra_incident()
    test_analyze_legitimate_chase()
    test_post_analyze()
    test_community_reporting_and_voting()
    test_threat_feed_and_samples()
    test_stix_export()
    print("==================================================")
    print(">> ALL TEST CASES PASSED WITH 100% SUCCESS! <<")
    print("==================================================")
