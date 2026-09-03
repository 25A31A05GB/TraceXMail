# TraceXMail Judge Defense Demo Cases & Test Fixtures
**Problem Statement:** Smart India Hackathon 2026 — PS 26106  
**Artifact Directory:** `data/demo_emails/`  
**Standard:** RFC 5322 EML Test Harness  

---

## Overview

This test suite contains five safe, reproducible, RFC-compliant `.eml` test fixtures representing the five primary operating scenarios evaluated by the TraceXMail forensic intelligence pipeline. Judges can upload or feed any of these raw files into TraceXMail to verify end-to-end parsing, header decoding, authentication verification, ML classification, and composite risk scoring.

---

## 1. Case Matrix

| Fixture File | Target Class | Expected Verdict | Expected Risk Tier | Primary Forensic Indicators |
| :--- | :--- | :--- | :--- | :--- |
| `legit_invoice.eml` | `Legitimate` | `LEGITIMATE` | **CLEAN / LOW (Score < 15)** | Full SPF/DKIM/DMARC Pass; Stripe verified domain; legitimate billing body. |
| `brand_impersonation.eml` | `Impersonated` | `IMPERSONATED` | **CRITICAL (Score 80–95)** | Display-name claims "DocuSign"; domain is unaligned lookalike (`docusign-envelope-review.net`); Reply-To diverted to external domain; SPF/DMARC fail. |
| `credential_harvesting.eml` | `Phishing` | `MALICIOUS PHISH` | **CRITICAL (Score 85–100)** | Fake SSO login portal link; SPF Hardfail; urgency lure; unknown Chinese ISP ingress relay. |
| `bec_wire_fraud.eml` | `Fraud-related` | `FRAUD-RELATED` | **CRITICAL (Score 80–95)** | Zero links, zero attachments; CEO identity impersonation; Reply-To diverted to Gmail; high-pressure wire transfer ($84,500) and IBAN instructions. |
| `suspicious_graymail.eml` | `Suspicious` | `SUSPICIOUS` | **MEDIUM (Score 35–55)** | Aggressive B2B cold outreach; opt-out unsubscribe footer; passing SPF/DKIM on dedicated marketing outbound domain. |

---

## 2. Detailed Case Analysis & Judge Evaluation Guide

### Case 1: `legit_invoice.eml`
- **File Location:** `data/demo_emails/legit_invoice.eml`
- **Simulated Scenario:** Authentic monthly cloud infrastructure invoice from Stripe.
- **Header Telemetry:**
  - `From: "Stripe Billing" <invoices@stripe.com>`
  - `Return-Path: <bounces+241@stripe.com>`
  - `Authentication-Results:` `dkim=pass (2048-bit key) header.d=stripe.com`, `spf=pass`, `dmarc=pass`
- **What the Judge Should Check in TraceXMail:**
  1. Cryptographic Authentication tab displays three green badges: SPF PASS, DKIM PASS, DMARC PASS.
  2. Domain alignment is 100% aligned (`header.from` matches `smtp.mailfrom` domain `stripe.com`).
  3. ML Classifier outputs `Legitimate` with high confidence.
  4. Composite Threat Score is $\le 10/100$ (CLEAN).

---

### Case 2: `brand_impersonation.eml`
- **File Location:** `data/demo_emails/brand_impersonation.eml`
- **Simulated Scenario:** Electronic signature agreement notice spoofing DocuSign.
- **Header Telemetry:**
  - `From: "DocuSign Electronic Signature Service" <service@docusign-envelope-review.net>`
  - `Reply-To: <diverted-reviews@secure-legal-docs.org>`
  - `Received:` Relay hop `185.220.101.5`
  - `Authentication-Results:` `spf=softfail`, `dkim=fail`, `dmarc=fail`
- **What the Judge Should Check in TraceXMail:**
  1. Header Inspector flags **Display Name vs Domain Mismatch**: Display name cites "DocuSign", but domain is `docusign-envelope-review.net`.
  2. Identity Heuristic flags **Reply-To Diversion**: Replies sent to `secure-legal-docs.org` instead of sender domain.
  3. ML Classifier outputs `Impersonated`.
  4. Composite Threat Score is $\ge 85/100$ (CRITICAL EXPOSURE).

---

### Case 3: `credential_harvesting.eml`
- **File Location:** `data/demo_emails/credential_harvesting.eml`
- **Simulated Scenario:** Corporate IT Active Directory password expiration notice with fake SSO login link.
- **Header Telemetry:**
  - `From: "IT Support Helpdesk" <alert@account-security-verification-portal.com>`
  - `Authentication-Results:` `spf=fail`, `dkim=none`, `dmarc=fail`
  - Body contains hyperlink to external credential harvester.
- **What the Judge Should Check in TraceXMail:**
  1. Authentication tab flags `SPF: FAIL` and `DMARC: FAIL`.
  2. URL Extractor isolates suspicious login link: `http://account-security-verification-portal.com/login/sso`.
  3. ML Classifier outputs `Phishing`.
  4. Ingress IP maps to external hosting ASN.

---

### Case 4: `bec_wire_fraud.eml`
- **File Location:** `data/demo_emails/bec_wire_fraud.eml`
- **Simulated Scenario:** Executive wire fraud (CEO Fraud) requesting immediate $84,500 wire transfer for confidential acquisition.
- **Header Telemetry:**
  - `From: "David Harrison (Chief Executive Officer)" <david.harrison@enterprise-corp.com>`
  - `Reply-To: "Executive Director Desk" <david.harrison.ceo.office@gmail.com>`
  - **No hyperlinks and no file attachments.**
- **What the Judge Should Check in TraceXMail:**
  1. Shows that TraceXMail successfully catches text-only attacks that traditional link/attachment scanners completely miss.
  2. Flags **Reply-To Hijack**: The display name claims the CEO's corporate address, but replies route directly to a personal Gmail account (`david.harrison.ceo.office@gmail.com`).
  3. NLP Deception Engine flags financial urgency triggers (`wire transfer`, `escrow`, `SWIFT`, `$84,500`).
  4. ML Classifier categorizes as `Fraud-related`.

---

### Case 5: `suspicious_graymail.eml`
- **File Location:** `data/demo_emails/suspicious_graymail.eml`
- **Simulated Scenario:** High-pressure unsolicited B2B lead generation cold outreach.
- **Header Telemetry:**
  - `From: "Alex Miller | Growth Acceleration" <alex.miller@outbound-lead-growth-system.io>`
  - `Authentication-Results:` `spf=pass`, `dkim=pass`, `dmarc=pass`
  - Unsubscribe link present in email footer.
- **What the Judge Should Check in TraceXMail:**
  1. Cryptographic authentication passes because modern outbound marketing engines configure proper SPF/DKIM records.
  2. NLP Content Classifier identifies marketing keywords (`pipeline`, `leads`, `unsubscribe`, `growth engine`) and categorizes the email as `Suspicious` (Graymail).
  3. Risk score remains moderate (35–55/100, MEDIUM), correctly distinguishing graymail from critical phishing or financial fraud.
