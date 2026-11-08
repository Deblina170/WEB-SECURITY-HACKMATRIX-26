# ThreatGuard // AI-Powered Web Threat Detection & Digital Trust Intelligence

An intelligent cyber threat detection and digital trust platform that unifies **phishing threat heuristics**, **web security assessment**, **cryptographic certificate validation**, and **collaborative threat intelligence**.

Built for **HackMatrix'26 Web Security Track**.

---

## 🏛️ Architecture & Module Structure

The platform is modularized into distinct, dedicated single-responsibility files as required by the specification:

```
WEB SECURITY HACKMATRIX'26/
├── threat.py             # AI Phishing heuristics, brand spoofing, typosquatting, credential forms
├── webscan.py            # Web posture, security headers (HSTS, CSP, etc.), cookie flags, leaks
├── certs.py              # X.509 cryptography, CA validation, eMudhra incident audit, CT logs
├── intel.py              # Collaborative threat intelligence, community reports, voting & feeds
├── risk.py               # Multi-vector risk aggregation, trust score, and explainable AI verdict
├── main.py               # FastAPI backend with core /analyze?url=... endpoint
├── database.py           # SQLite database layer for IOC feeds, community reports, and history
├── network_utils.py      # Non-blocking DNS & network helper
├── test_api.py           # Comprehensive automated test suite
├── requirements.txt      # Project dependencies
└── static/               # Cyber Defense Command Center Frontend
    ├── index.html        # Interactive dashboard
    ├── style.css         # Dark cyberpunk styling & SVG trust gauge
    └── app.js            # Frontend reactive logic & API integration
```

---

## 🚀 Key Security Capabilities

### 1. Phishing & Threat Analysis (`threat.py`)
- **Brand Impersonation & Typosquatting**:
  - Fuzzy distance matching against 40+ high-profile brands (PayPal, Chase, Amazon, Microsoft, Google, eMudhra, etc.).
  - Levenshtein distance detection for character substitutions (`1` for `l`, `0` for `o`, `rn` for `m`).
  - IDN Homograph / Punycode (`xn--`) character spoofing detection.
- **Domain Lexical Heuristics**:
  - Shannon entropy calculation to detect Algorithmically Generated Domains (DGA).
  - Excessive subdomain depth, suspicious TLDs (`.tk`, `.xyz`, `.top`, `.buzz`), and IP-as-host detection.
- **Credential Harvesting Inspection**:
  - HTML parser auditing password fields, banking inputs, and sensitive data prompts.
  - Insecure unencrypted HTTP form submissions and cross-domain credential exfiltration.

### 2. Web Security Assessment (`webscan.py`)
- **Security Headers Evaluation & Letter Grade (A+ to F)**:
  - `Strict-Transport-Security` (HSTS) with max-age, subdomains, and preload checks.
  - `Content-Security-Policy` (CSP) with `unsafe-inline` and `unsafe-eval` warnings.
  - `X-Frame-Options` (Clickjacking mitigation).
  - `X-Content-Type-Options` (nosniff MIME protection).
  - `Referrer-Policy` & `Permissions-Policy`.
- **Information Disclosure**:
  - Detects server technology leaks (`Server`, `X-Powered-By`, `X-AspNet-Version`).
- **Cookie & Mixed Content**:
  - Cookie security audit (`Secure`, `HttpOnly`, `SameSite`).
  - Mixed content scanner detecting insecure HTTP subresources on HTTPS pages.

### 3. Digital Trust & Certificate Validation (`certs.py`)
- **Deep Cryptographic X.509 Inspection**:
  - Public Key Strength: Flags weak RSA keys (< 2048 bits) as critical vulnerabilities.
  - Signature Hash Algorithms: Flags deprecated collision-prone hashes (MD5, SHA-1).
  - Subject Alternative Names (SANs) & Domain matching.
  - CA/B Forum 398-day maximum validity compliance.
- **⚡ The eMudhra TLS Certificate Incident Intelligence**:
  - **Context**: The eMudhra incident highlighted severe risks where Certificate Authority key generation flaws could yield predictable or duplicate cryptographic keys, enabling unauthorized MITM decryption and website impersonation.
  - **Mitigation & Detection**:
    - Flags eMudhra-issued certificates exhibiting weak RSA key sizes (<= 1024-bit).
    - Checks for embedded **Signed Certificate Timestamps (SCTs)** per Certificate Transparency (CT) standards (`1.3.6.1.4.1.11129.2.4.2`).
    - Detects fraudulent intermediate certificates and domain impersonators masquerading as eMudhra Trust Services.

### 4. Collaborative Threat Intelligence (`intel.py`)
- **Crowdsourced Intelligence & Reputation**:
  - Users and security analysts can submit live threat reports with category, brand, and evidence notes.
  - Crowd upvoting/downvoting mechanism with IP-duplicate protection to establish consensus.
- **IOC Threat Feeds**:
  - SQLite-backed Indicators of Compromise (IOC) registry pre-populated with threat signatures.
  - Calculates a real-time community reputation score.
- **☁️ Hybrid Database Architecture (Supabase PostgreSQL + SQLite Failover)**:
  - Supports dynamic cloud connection to **Supabase (PostgreSQL)** for multi-device live threat sharing.
  - Features **automatic air-gapped failover to local SQLite** so the system operates with 100% reliability offline with zero network latency.
  - Inspect active persistence engine via `GET /api/system/db-status`.

### 5. Unified Explainable Risk Engine (`risk.py`)
- **Weighted Multi-Vector Scoring**:
  - Threat Heuristics: **35%**
  - Digital Trust & Certs: **25%**
  - Web Security Posture: **20%**
  - Collaborative Intel: **20%**
- **Outputs**:
  - **Digital Trust Score (0 to 100)**: Higher is safer.
  - **Risk Level**: `CRITICAL`, `HIGH`, `MODERATE`, `LOW`, `CLEAN`.
  - **Explainable Rationale**: Natural language verdict explaining why the target is unsafe.
  - **Actionable Remediation**: End-user safety guidance + Administrator hardening steps.

---

## 📡 Core API Specification

### 1. Core Analyze Endpoint (Primary Requirement)
```http
GET /analyze?url=https://chase.com
```
Also supports `POST /analyze` with JSON:
```json
{
  "url": "https://chase.com"
}
```

#### Example Response:
```json
{
  "status": "success",
  "scan_id": "9d8e7c6b-...",
  "target_url": "https://chase.com",
  "domain": "chase.com",
  "verdict": {
    "risk_level": "CLEAN",
    "risk_score": 1,
    "trust_score": 99,
    "badge_color": "green",
    "summary": "VERIFIED: 'chase.com' exhibits healthy security hygiene...",
    "breakdown": {
      "threat_heuristics": { "score": 0, "status": "CLEAN" },
      "digital_trust_certs": { "trust_score": 100, "status": "VALID" },
      "web_security_posture": { "grade": "A", "headers_score": 90 },
      "collaborative_intelligence": { "verdict": "CLEAN" }
    }
  },
  "threat_analysis": { ... },
  "certificate_analysis": { ... },
  "web_security": { ... },
  "threat_intelligence": { ... },
  "recommendations": { ... }
}
```

### 2. Other Endpoints
- `GET /api/threats/stix` — **OASIS STIX 2.1 Enterprise Threat Intelligence Bundle** for SIEM/SOAR ingestion (Splunk, Sentinel, MISP).
- `POST /api/intel/report` — Submit a collaborative threat report.
- `POST /api/intel/vote` — Vote on an existing report.
- `GET /api/threats/feed` — Retrieve live global IOC threat feed.
- `GET /api/samples` — Retrieve curated demonstration test cases.
- `GET /api/history` — Scan audit logs.
- `GET /health` — Health check.
- `GET /docs` — Interactive OpenAPI / Swagger UI.

---

## 🛠️ Installation & Running

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Automated Test Suite
```bash
python test_api.py
```
*All tests pass with 100% assertions across all modules.*

### 3. Launch the Server
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Then open your browser to:
- **Web UI**: `http://127.0.0.1:8000/`
- **Core API Endpoint**: `http://127.0.0.1:8000/analyze?url=https://chase.com`
- **Swagger Documentation**: `http://127.0.0.1:8000/docs`
