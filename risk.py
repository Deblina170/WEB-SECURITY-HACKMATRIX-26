"""
Composite Risk Engine & Explainable AI Module (risk.py)
Aggregates multi-vector findings from threat analysis, digital certificate trust,
web security posture, and collaborative threat intelligence into a unified
risk rating, trust score, explainable verdict, and remediation guidance.
"""
from typing import Dict, Any, List

def calculate_composite_risk(
    threat_data: Dict[str, Any],
    cert_data: Dict[str, Any],
    web_data: Dict[str, Any],
    intel_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Synthesizes multi-vector security evaluations into an explainable
    composite risk profile and digital trust score.
    """
    # 1. Component Risk Scores (0 = Safe, 100 = Critical Danger)
    threat_score = threat_data.get("threat_score", 0)
    
    # Cert risk points (inverse of trust score)
    cert_risk_score = cert_data.get("risk_points", 0)
    
    # Web vulnerability risk score
    web_risk_score = web_data.get("web_risk_score", 0)
    
    # Collaborative intelligence risk points
    intel_risk_score = intel_data.get("intel_risk_points", 0)

    # 2. Weighted Aggregation:
    # Phishing/Threat: 35%, Digital Trust/Certs: 25%, Web Posture: 20%, Collaborative Intel: 20%
    weighted_score = (
        threat_score * 0.35 +
        cert_risk_score * 0.25 +
        web_risk_score * 0.20 +
        intel_risk_score * 0.20
    )

    # Overrides / Critical Kill-Switches:
    # If active phishing or confirmed malicious IOC or critical CA key weakness is present,
    # elevate risk score to minimum 85.
    is_phishing = threat_data.get("is_phishing", False)
    is_malicious_ioc = intel_data.get("threat_verdict") == "CONFIRMED_MALICIOUS"
    is_critical_ca_weakness = (
        cert_data.get("emudhra_incident_analysis", {}).get("advisory_status") == "CRITICAL_KEY_WEAKNESS"
        or cert_data.get("status") == "UNTRUSTED_CRITICAL"
    )

    if (is_phishing and threat_score >= 60) or is_malicious_ioc or is_critical_ca_weakness:
        final_risk_score = max(int(round(weighted_score)), 85)
    else:
        final_risk_score = min(100, max(0, int(round(weighted_score))))

    trust_score = max(0, 100 - final_risk_score)

    # 3. Categorize Risk Level
    if final_risk_score >= 80:
        risk_level = "CRITICAL"
        badge_color = "red"
    elif final_risk_score >= 60:
        risk_level = "HIGH"
        badge_color = "orange"
    elif final_risk_score >= 40:
        risk_level = "MODERATE"
        badge_color = "yellow"
    elif final_risk_score >= 15:
        risk_level = "LOW"
        badge_color = "blue"
    else:
        risk_level = "CLEAN"
        badge_color = "green"

    # 4. Generate Explainable Factors and Key Threats
    threat_factors = []
    
    # Threat module findings
    if threat_data.get("impersonated_brand"):
        threat_factors.append({
            "vector": "Brand Impersonation",
            "severity": "CRITICAL",
            "message": f"Detected unauthorized spoofing of brand '{threat_data['impersonated_brand']}'."
        })
    if threat_data.get("credential_harvesting_detected"):
        threat_factors.append({
            "vector": "Credential Harvesting",
            "severity": "CRITICAL",
            "message": "Page contains password or financial credential input forms."
        })
    if threat_data.get("fake_recruitment_detected"):
        threat_factors.append({
            "vector": "Recruitment Fraud",
            "severity": "HIGH",
            "message": "Domain and URL pattern exhibit fraudulent recruitment and employment scam lures."
        })
    if threat_data.get("is_punycode"):
        threat_factors.append({
            "vector": "Homograph Attack",
            "severity": "HIGH",
            "message": "Internationalized Domain Name (Punycode) detected; may mimic legitimate Latin characters."
        })

    # Certificate & Digital Trust findings
    emudhra_adv = cert_data.get("emudhra_incident_analysis", {})
    if emudhra_adv.get("advisory_status") == "CRITICAL_KEY_WEAKNESS":
        threat_factors.append({
            "vector": "Digital Trust / CA Infrastructure",
            "severity": "CRITICAL",
            "message": "Certificate matches weak key generation patterns flagged in the eMudhra TLS incident advisory."
        })
    if cert_data.get("trust_chain", {}).get("is_self_signed"):
        threat_factors.append({
            "vector": "Certificate Trust",
            "severity": "HIGH",
            "message": "Self-signed certificate is not validated by any recognized public Certificate Authority."
        })
    if not cert_data.get("trust_chain", {}).get("has_certificate_transparency_sct") and not cert_data.get("trust_chain", {}).get("is_self_signed"):
        threat_factors.append({
            "vector": "Certificate Transparency",
            "severity": "MEDIUM",
            "message": "Missing Signed Certificate Timestamps (SCTs) required for CT log auditing."
        })
    if cert_data.get("cryptography", {}).get("key_size_bits", 2048) < 2048:
        threat_factors.append({
            "vector": "Cryptographic Key Size",
            "severity": "CRITICAL",
            "message": f"Weak RSA key size ({cert_data.get('cryptography', {}).get('key_size_bits')} bits) is inadequate for modern encryption."
        })

    # Web Posture findings
    if not web_data.get("is_https"):
        threat_factors.append({
            "vector": "Transport Security",
            "severity": "HIGH",
            "message": "Connection is unencrypted HTTP, exposing all traffic to eavesdropping and interception."
        })
    if web_data.get("missing_headers") and len(web_data.get("missing_headers")) >= 3:
        threat_factors.append({
            "vector": "Security Headers",
            "severity": "MEDIUM",
            "message": f"Missing critical browser security headers: {', '.join(web_data['missing_headers'][:3])}."
        })

    # Collaborative Intel findings
    if intel_data.get("matched_iocs_count", 0) > 0:
        threat_factors.append({
            "vector": "Threat Intelligence Feed",
            "severity": "CRITICAL",
            "message": f"Matched {intel_data['matched_iocs_count']} active Indicator(s) of Compromise in global threat feeds."
        })
    if intel_data.get("community_reports_count", 0) > 0:
        threat_factors.append({
            "vector": "Collaborative Threat Reports",
            "severity": "HIGH",
            "message": f"{intel_data['community_reports_count']} crowdsourced threat reports submitted by analysts/users."
        })

    # 5. Natural Language AI Verdict
    domain = threat_data.get("domain", "")
    if risk_level in ["CRITICAL", "HIGH"]:
        summary_verdict = (
            f"ALERT: '{domain}' poses a severe security danger. Multi-vector analysis identified active "
            f"{threat_data.get('impersonated_brand', 'malicious') + ' impersonation and ' if threat_data.get('impersonated_brand') else ''}"
            f"high-risk indicators including credential harvesting vectors and digital trust anomalies. "
            f"Do not interact with or provide sensitive information to this website."
        )
    elif risk_level == "MODERATE":
        summary_verdict = (
            f"CAUTION: '{domain}' presents moderate security deficiencies. While not definitively flagged "
            f"as an active threat feed exploit, it demonstrates multiple web configuration weaknesses and "
            f"cryptographic or header posture gaps requiring caution."
        )
    else:
        summary_verdict = (
            f"VERIFIED: '{domain}' exhibits healthy security hygiene. Verified Certificate Authority "
            f"infrastructure, robust cryptographic parameters, and no matching malicious indicators "
            f"in collaborative threat intelligence databases."
        )

    # 6. Actionable Recommendations
    user_guidance = []
    admin_remediation = []

    if risk_level in ["CRITICAL", "HIGH"]:
        user_guidance.append("Do NOT submit any credentials, phone numbers, OTPs, or payment information on this page.")
        user_guidance.append("Close browser tabs pointing to this URL and clear local site cookies.")
        user_guidance.append("If credentials were already submitted, immediately change passwords on the official service and enable 2-factor authentication.")
    elif risk_level == "MODERATE":
        user_guidance.append("Verify the URL carefully in the address bar before logging in.")
        user_guidance.append("Ensure HTTPS padlock is present and the certificate issuer is recognized.")
    else:
        user_guidance.append("Site appears safe for normal navigation. Exercise standard browsing vigilance.")

    # Admin Remediation
    if not web_data.get("is_https"):
        admin_remediation.append("Install an X.509 TLS certificate from an authorized CA and redirect all HTTP traffic to HTTPS.")
    if cert_data.get("cryptography", {}).get("key_size_bits", 2048) < 2048:
        admin_remediation.append("Regenerate TLS certificate private key with minimum RSA 2048-bit modulus or ECDSA P-256 curve.")
    if "Strict-Transport-Security" in web_data.get("missing_headers", []):
        admin_remediation.append("Implement Strict-Transport-Security (HSTS) with 'max-age=31536000; includeSubDomains; preload'.")
    if "Content-Security-Policy" in web_data.get("missing_headers", []):
        admin_remediation.append("Deploy a restrictive Content-Security-Policy (CSP) to mitigate cross-site scripting (XSS) and unauthorized framing.")
    if "X-Frame-Options" in web_data.get("missing_headers", []):
        admin_remediation.append("Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking attacks.")
    if web_data.get("information_leaks"):
        admin_remediation.append("Disable server banners (Server, X-Powered-By) to prevent automated adversary technology fingerprinting.")
    if emudhra_adv.get("advisory_status") in ["CRITICAL_KEY_WEAKNESS", "SUSPICIOUS_UNLOGGED_CERT"]:
        admin_remediation.append("Audit Certificate Authority root chain and ensure compliance with post-incident Certificate Transparency requirements.")

    return {
        "risk_level": risk_level,
        "badge_color": badge_color,
        "composite_risk_score": final_risk_score,
        "digital_trust_score": trust_score,
        "summary_verdict": summary_verdict,
        "threat_factors": threat_factors,
        "user_guidance": user_guidance,
        "admin_remediation": admin_remediation,
        "breakdown": {
            "threat_heuristics": {
                "score": threat_score,
                "weight": "35%",
                "status": threat_data.get("threat_level")
            },
            "digital_trust_certs": {
                "score": cert_risk_score,
                "trust_score": cert_data.get("trust_score"),
                "weight": "25%",
                "status": cert_data.get("status")
            },
            "web_security_posture": {
                "score": web_risk_score,
                "grade": web_data.get("security_grade"),
                "weight": "20%",
                "headers_score": web_data.get("headers_score")
            },
            "collaborative_intelligence": {
                "score": intel_risk_score,
                "weight": "20%",
                "verdict": intel_data.get("threat_verdict"),
                "consensus": intel_data.get("community_consensus", {}).get("reliability")
            }
        }
    }
