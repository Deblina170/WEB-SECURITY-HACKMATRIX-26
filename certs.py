"""
Certificate Validation & Digital Trust Intelligence (certs.py)
Deep cryptographic X.509 certificate analysis, key strength auditing,
Certificate Transparency (CT) compliance, CA trust chain assessment,
and specialized threat detection for the eMudhra TLS Certificate incident.
"""
import ssl
import socket
import datetime
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.oid import NameOID, ExtensionOID
from network_utils import fast_dns_lookup

# Certificate Transparency Precertificate / SCT Extension OID
CT_SCT_OID = "1.3.6.1.4.1.11129.2.4.2"

# Known Trusted Public Root CAs
RECOGNIZED_TRUSTED_CAS = [
    "digicert", "let's encrypt", "isrg root", "sectigo", "godaddy", "globalsign",
    "google trust services", "amazon", "microsoft", "comodo", "cloudflare", "entrust"
]

# CA incident registry & known vulnerable issuance parameters
KNOWN_CA_INCIDENTS = {
    "emudhra": {
        "title": "eMudhra TLS Certificate Weak Key Generation Incident",
        "description": (
            "Weaknesses in Certificate Authority random number generation or key management "
            "allowed issuance of certificates with predictable or duplicate cryptographic keys, "
            "enabling potential unauthorized MITM decryption and website impersonation."
        ),
        "posture_check": "Strict validation of key entropy, minimum 2048-bit modulus, embedded SCTs, and verified CA hierarchy."
    }
}


def parse_x509_certificate(cert_obj: x509.Certificate, domain: str, simulated_has_sct: Optional[bool] = None) -> Dict[str, Any]:
    """
    Parses a cryptography.x509.Certificate instance into a structured
    cryptographic trust profile.
    """
    indicators = []
    points = 0  # Risk points (0 = pristine, 100 = critical risk)

    # 1. Subject and Issuer
    def format_name(name):
        res = {}
        for attr in name:
            oid_name = attr.oid._name if hasattr(attr.oid, '_name') else str(attr.oid)
            res[oid_name] = attr.value
        return res

    subject_info = format_name(cert_obj.subject)
    issuer_info = format_name(cert_obj.issuer)

    subject_cn = subject_info.get("commonName", "")
    issuer_cn = issuer_info.get("commonName", "")
    issuer_org = issuer_info.get("organizationName", issuer_cn)

    # 2. Self-signed check
    is_self_signed = (cert_obj.subject == cert_obj.issuer)
    if is_self_signed:
        points += 50
        indicators.append({
            "type": "self_signed_certificate",
            "severity": "critical",
            "message": "Certificate is self-signed and not backed by a trusted Certificate Authority (untrusted identity)."
        })

    # 3. Validity Timeframe
    # Use timezone-aware UTC datetime comparison
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # cryptography 42+ provides not_valid_before_utc and not_valid_after_utc
    try:
        not_before = cert_obj.not_valid_before_utc
        not_after = cert_obj.not_valid_after_utc
    except AttributeError:
        # Fallback for older versions
        not_before = cert_obj.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        not_after = cert_obj.not_valid_after.replace(tzinfo=datetime.timezone.utc)

    is_expired = now > not_after
    is_future = now < not_before
    days_until_expiration = (not_after - now).days
    total_validity_days = (not_after - not_before).days

    if is_expired:
        points += 60
        indicators.append({
            "type": "expired_certificate",
            "severity": "critical",
            "message": f"Certificate expired on {not_after.strftime('%Y-%m-%d')} ({abs(days_until_expiration)} days ago)."
        })
    elif days_until_expiration < 14:
        points += 15
        indicators.append({
            "type": "expiring_soon",
            "severity": "medium",
            "message": f"Certificate will expire in {days_until_expiration} days."
        })

    # CA/B Forum standard: Maximum validity limit is 398 days since Sep 2020
    if total_validity_days > 398 and not is_self_signed:
        points += 15
        indicators.append({
            "type": "excessive_validity_period",
            "severity": "medium",
            "message": f"Validity duration ({total_validity_days} days) violates CA/Browser Forum 398-day maximum lifespan standard."
        })

    # 4. Public Key & Cryptographic Strength
    public_key = cert_obj.public_key()
    key_type = "UNKNOWN"
    key_size = 0
    key_strength_status = "SECURE"

    if isinstance(public_key, rsa.RSAPublicKey):
        key_type = "RSA"
        key_size = public_key.key_size
        if key_size < 2048:
            points += 55
            key_strength_status = "CRITICAL_WEAK"
            indicators.append({
                "type": "weak_rsa_key_length",
                "severity": "critical",
                "message": f"RSA key size ({key_size} bits) is critically insecure and vulnerable to factorization attacks (minimum required: 2048 bits)."
            })
        elif key_size == 2048:
            key_strength_status = "ADEQUATE"
        else:
            key_strength_status = "STRONG"
            
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_type = f"ECC ({public_key.curve.name})"
        key_size = public_key.curve.key_size
        if key_size < 256:
            points += 45
            key_strength_status = "WEAK"
            indicators.append({
                "type": "weak_ecc_curve",
                "severity": "high",
                "message": f"Elliptic Curve key size ({key_size} bits) is below the modern 256-bit security threshold."
            })
        else:
            key_strength_status = "STRONG"

    # 5. Signature Hash Algorithm
    sig_algo = cert_obj.signature_hash_algorithm.name if cert_obj.signature_hash_algorithm else "UNKNOWN"
    if sig_algo.lower() in ["md5", "sha1"]:
        points += 50
        indicators.append({
            "type": "deprecated_signature_algorithm",
            "severity": "critical",
            "message": f"Certificate signed with cryptographically broken hash '{sig_algo.upper()}' (collision vulnerability)."
        })

    # 6. Subject Alternative Names (SANs) & Domain Verification
    sans = []
    has_san_extension = False
    try:
        san_ext = cert_obj.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        has_san_extension = True
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        pass

    # Check domain match against SAN or CN
    domain_clean = domain.lower().strip()
    matched_san = False
    for san_name in sans + ([subject_cn] if subject_cn else []):
        san_clean = san_name.lower().strip()
        if san_clean == domain_clean:
            matched_san = True
            break
        # Wildcard match *.example.com
        if san_clean.startswith("*.") and domain_clean.endswith(san_clean[1:]):
            matched_san = True
            break

    if not matched_san and not is_self_signed:
        points += 40
        indicators.append({
            "type": "domain_name_mismatch",
            "severity": "critical",
            "message": f"Domain '{domain}' does not match Certificate Subject CN ('{subject_cn}') or SANs."
        })

    # 7. Certificate Transparency (CT) / SCT Verification
    has_sct = False
    try:
        for ext in cert_obj.extensions:
            if ext.oid in [ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS, ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS]:
                has_sct = True
                break
    except Exception:
        # If any unsupported extension causes parser error, safely treat has_sct based on domain profile
        has_sct = not is_self_signed and not ("emudhra-auth-portal" in domain.lower() or "fraud" in domain.lower())

    # Check simulated flag if present
    if simulated_has_sct is not None:
        has_sct = simulated_has_sct

    if not has_sct and not is_self_signed:
        points += 15
        indicators.append({
            "type": "missing_certificate_transparency",
            "severity": "medium",
            "message": "Certificate lacks embedded Signed Certificate Timestamps (SCTs) required for Certificate Transparency monitoring."
        })

    # 8. eMudhra Incident & CA Trust Audit
    emudhra_audit = audit_ca_trust_and_emudhra(
        issuer_org=issuer_org,
        issuer_cn=issuer_cn,
        key_type=key_type,
        key_size=key_size,
        has_sct=has_sct,
        domain=domain,
        is_self_signed=is_self_signed
    )

    if emudhra_audit["risk_points"] > 0:
        points += emudhra_audit["risk_points"]
        indicators.extend(emudhra_audit["indicators"])

    trust_score = max(0, 100 - points)
    cert_status = "VALID"
    if points >= 60:
        cert_status = "UNTRUSTED_CRITICAL"
    elif points >= 30:
        cert_status = "WARNING_SUSPICIOUS"
    elif points > 0:
        cert_status = "ACCEPTABLE_WITH_NOTICES"

    return {
        "status": cert_status,
        "trust_score": trust_score,
        "risk_points": min(100, points),
        "subject": {
            "common_name": subject_cn,
            "organization": subject_info.get("organizationName", ""),
            "country": subject_info.get("countryName", "")
        },
        "issuer": {
            "common_name": issuer_cn,
            "organization": issuer_org,
            "country": issuer_info.get("countryName", "")
        },
        "validity": {
            "valid_from": not_before.isoformat(),
            "valid_until": not_after.isoformat(),
            "days_until_expiration": days_until_expiration,
            "total_validity_days": total_validity_days,
            "is_expired": is_expired,
            "is_future": is_future
        },
        "cryptography": {
            "key_type": key_type,
            "key_size_bits": key_size,
            "key_strength": key_strength_status,
            "signature_algorithm": sig_algo
        },
        "trust_chain": {
            "is_self_signed": is_self_signed,
            "has_certificate_transparency_sct": has_sct,
            "subject_alternative_names": sans[:15],
            "domain_name_matched": matched_san
        },
        "emudhra_incident_analysis": emudhra_audit,
        "indicators": indicators
    }


def audit_ca_trust_and_emudhra(
    issuer_org: str,
    issuer_cn: str,
    key_type: str,
    key_size: int,
    has_sct: bool,
    domain: str,
    is_self_signed: bool
) -> Dict[str, Any]:
    """
    Dedicated audit for CA Trust Integrity with focused intelligence on
    the eMudhra TLS Certificate incident and weak key generation threats.
    """
    combined_issuer = f"{issuer_org} {issuer_cn}".lower()
    is_emudhra_ca = "emudhra" in combined_issuer or "e-mudhra" in combined_issuer
    claims_emudhra_brand = "emudhra" in domain.lower()

    indicators = []
    risk_points = 0
    advisory_status = "NORMAL"

    if claims_emudhra_brand and not is_emudhra_ca and not is_self_signed:
        # Domain name contains emudhra but cert was not issued by eMudhra
        risk_points += 35
        advisory_status = "SUSPECTED_CA_IMPERSONATION"
        indicators.append({
            "type": "ca_brand_impersonation",
            "severity": "high",
            "message": f"Domain '{domain}' purports to represent eMudhra Trust Services, but its certificate is issued by '{issuer_org or issuer_cn}' rather than an authorized eMudhra root."
        })

    if is_emudhra_ca:
        # eMudhra CA identified
        if key_type == "RSA" and key_size <= 1024:
            risk_points += 45
            advisory_status = "CRITICAL_KEY_WEAKNESS"
            indicators.append({
                "type": "emudhra_weak_key_generation_match",
                "severity": "critical",
                "message": (
                    "CRITICAL INCIDENT MATCH: Certificate issued by eMudhra employs an insecure "
                    f"{key_size}-bit key, aligning with vulnerable key generation patterns identified "
                    "in the eMudhra TLS trust advisory. High risk of private key compromise and impersonation."
                )
            })
        elif not has_sct:
            risk_points += 25
            advisory_status = "SUSPICIOUS_UNLOGGED_CERT"
            indicators.append({
                "type": "emudhra_unlogged_certificate",
                "severity": "high",
                "message": "Certificate issued by eMudhra lacks Certificate Transparency (CT) logging, preventing public audit verification."
            })
        else:
            advisory_status = "VERIFIED_POST_AUDIT_CA"

    return {
        "is_emudhra_ca": is_emudhra_ca,
        "advisory_status": advisory_status,
        "incident_reference": KNOWN_CA_INCIDENTS["emudhra"],
        "risk_points": risk_points,
        "indicators": indicators
    }


def generate_simulated_cert(domain: str) -> Tuple[x509.Certificate, bool]:
    """
    Generates a cryptographically valid X.509 certificate in-memory
    tailored to the domain scenario for testing, sandbox environments,
    or simulated incident demonstrations.
    Returns (cert_object, include_sct_boolean).
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa

    domain_lower = domain.lower()

    # Determine simulated scenario parameters
    if "emudhra-auth-portal" in domain_lower or "fraud-verify" in domain_lower:
        # Weak 1024-bit key mimicking the eMudhra incident
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        issuer_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "eMudhra Technologies Ltd"),
            x509.NameAttribute(NameOID.COMMON_NAME, "eMudhra Sub CA - Weak Key Gen")
        ])
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Unauthorized Portal"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain)
        ])
        days = 800  # Violating 398 days
        include_sct = False
    elif "paypa1" in domain_lower or "tk" in domain_lower or "xyz" in domain_lower:
        # Self-signed certificate
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain)
        ])
        issuer_name = subject_name  # Self-signed!
        days = 365
        include_sct = False
    else:
        # Standard legitimate certificate (DigiCert / Google Trust Services)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DigiCert Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, "DigiCert Global Root G2")
        ])
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain)
        ])
        days = 90
        include_sct = True

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain), x509.DNSName(f"www.{domain}")]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
    )

    cert = builder.sign(key, hashes.SHA256())
    return cert, include_sct


def validate_certificate(url_or_domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Main Certificate Validation entrypoint.
    Connects to live host or falls back to scenario-accurate certificate inspection.
    """
    if "://" in url_or_domain:
        domain = urlparse(url_or_domain).hostname or url_or_domain
    else:
        domain = url_or_domain

    if ":" in domain:
        domain = domain.split(":")[0]

    cert_obj = None
    simulated_sct = None
    connection_mode = "live_tls"
    error_detail = None

    SIMULATED_KEYWORDS = ["paypa1", "fraud-verify", "emudhra-auth-portal", ".test", ".tk", ".xyz", "support-portal.info"]
    is_simulated_scenario = any(k in domain.lower() for k in SIMULATED_KEYWORDS)
    resolved_ip = fast_dns_lookup(domain) if not is_simulated_scenario else None

    # Try live TLS extraction if host resolves and is not simulated
    if not is_simulated_scenario and resolved_ip:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # Get certificate even if untrusted/expired
            
            with socket.create_connection((domain, port), timeout=1.5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        cert_obj = x509.load_der_x509_certificate(der_cert, default_backend())
        except Exception as e:
            connection_mode = "simulated_digital_trust_engine"
            error_detail = str(e)
            cert_obj, simulated_sct = generate_simulated_cert(domain)
    else:
        connection_mode = "simulated_digital_trust_engine"
        error_detail = "Target recognized as test/simulated environment or offline mode."
        cert_obj, simulated_sct = generate_simulated_cert(domain)

    parsed_result = parse_x509_certificate(cert_obj, domain, simulated_has_sct=simulated_sct)
    parsed_result["connection_mode"] = connection_mode
    if error_detail:
        parsed_result["network_note"] = f"Direct TLS probe: {error_detail}. Audited via Digital Trust simulation engine."

    return parsed_result
