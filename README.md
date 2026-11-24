# PRAMAAN (प्रमाण) · National Forensic Evidence & Remote Supervision Prototype
**An idea by Lokesh Bhavsar · Central University of Jammu · November 2026**
*Full-Stack Implementation compliant with Section 176(3) BNSS 2023 & Section 63 BSA 2023*

---

## 🏛️ Executive Summary

Under **Section 176(3) of the Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023**, forensic expert visits and mobile phone videography are **mandatory** for every offence punishable by seven years or more. 

With only **136 government forensic laboratories** serving a population of 1.4 billion and **40% vacancy** in scientific posts, physical travel by experts to 400+ scenes per district per year is mathematically impossible.

**Pramaan solves this gap through three core pillars:**
1. **Guided Field Capture (Module 1):** One-handed, touch-optimized capture checklist for investigating officers at 2 AM with low-latency live video streaming.
2. **Cryptographic Chain of Custody (Module 2):** Point-of-capture SHA-256 fingerprinting, Merkle-style chained audit ledger, and automated Section 63 BSA electronic certificates.
3. **Laboratory Triage & Pendency Intelligence (Module 3):** Batches evidence into specialized scientific divisions (Biology/DNA, Ballistics, Toxicology, Cyber) and balances regional workloads in real time.

---

## 🚀 Quick Start Instructions

To run the application locally on your Android/Termux environment or any server:

```bash
cd /data/data/com.termux/files/home/pramaan-prototype
node server.js
```

Then open your browser and navigate to:
**http://localhost:3000** (or `http://127.0.0.1:3000`)

---

## 🔑 Pre-Configured Demo Accounts

For immediate evaluation, the application includes a quick **"VIEW AS"** dropdown in the top navigation bar, or you can log in directly using the following credentials:

| Role | User Name | Email | Password | Scope & Responsibilities |
| :--- | :--- | :--- | :--- | :--- |
| **Investigating Officer** | SI Rajesh Sharma | `officer@pramaan.gov.in` | `Officer@123` | Locus delicti capture, 360° pan, exhibit tagging, seal logging |
| **Forensic Scientist** | Dr. Aditi Varma | `expert@pramaan.gov.in` | `Expert@123` | Remote live supervision, canvas annotation pins, DFSS directives, verification |
| **FSL Lab Director** | Dr. K. S. Meena | `director@pramaan.gov.in` | `Director@123` | District pendency tracking, division queue balancing, SLA management |
| **Magistrate / Court** | Hon. R. P. Sundaram | `magistrate@pramaan.gov.in` | `Magistrate@123` | Judicial record review, Section 63 BSA certificates, public hash validation |

---

## 🛡️ Security & Forensic Integrity Architecture

1. **Cryptographic Fingerprinting at Point of Capture:**
   - Every photograph, video stream slice, and physical exhibit has its SHA-256 hash computed at capture time before leaving the field device.
2. **Chained Immutable Custody Ledger:**
   - Custody transfer blocks contain:
     `SHA-256(previous_hash || exhibit_id || event_type || timestamp || to_person || seal_condition || actor_id)`
   - Any modification or database tampering instantly breaks the hash chain and is flagged as an evidentiary violation.
3. **BSA Section 63 Electronic Evidence Certificate:**
   - Generates court-admissible electronic records complete with hardware identifiers, NTP-synchronized timestamps, and HMAC verification tokens.
4. **Zero-Trust Hardening:**
   - PBKDF2 with 100,000 iterations and 64-byte salts for password storage.
   - Brute-force rate limiting (automatic 15-minute lock after 5 failed attempts).
   - SQL injection prevention via 100% parameterized SQLite prepared statements.
   - Strict Content Security Policy (`CSP`), `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`.
   - Public / Defense Counsel verification sandbox for independent hash validation without granting unauthorized database access.

---

## 📂 Project Directory Structure

```
pramaan-prototype/
├── server.js              # HTTP server, REST API, SSE real-time dispatcher, security middleware
├── db.js                  # SQLite engine with node:sqlite, table schemas & BNSS pre-seeded records
├── auth.js                # PBKDF2 hashing, session management, rate limiter, timing-safe checks
├── crypto-engine.js       # SHA-256 engine, chained Merkle ledger, BSA Section 63 HMAC generator
├── test_system.js         # Automated end-to-end verification test suite
├── start.sh               # One-click execution launcher
├── data/
│   └── pramaan.sqlite     # Persistent SQLite database
├── uploads/               # Secure evidentiary media vault
└── public/
    ├── index.html         # Responsive GovTech SPA with 6 dedicated tabs
    ├── app.js             # Client state, canvas video simulation, interactive annotation engine
    └── styles.css         # 2 AM Crime Scene Night Mode & Daylight Forensic theme
```
