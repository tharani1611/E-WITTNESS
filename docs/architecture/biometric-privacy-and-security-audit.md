# E-WITNESS Biometric Privacy, Security, Accuracy and Governance Audit (Phases 71–80)

**Document Reference**: `E-WITNESS-AUD-BIO-08`  
**Classification**: High-Assurance Architectural Audit  
**Status**: Formal Audit Finalized — **MANDATORY PRODUCTION NO-GO FOR BIOMETRIC MATCHING**  
**Effective Date**: 2026-10-14  

---

## Executive Summary & Final Verdict

This audit formalizes the comprehensive technical, legal, cryptographic, and operational review of all biometric capabilities implemented across **Batch 08 (Phases 71–80)** in E-WITNESS.

### Mandatory Operational Decision

> [!CAUTION]
> ### FINAL VERDICT: **NO-GO FOR PRODUCTION BIOMETRIC MATCHING**
> 
> Biometric face matching / identification (`BIOMETRIC_MATCHING_ENABLED`) is **STRICTLY PROHIBITED** in production environments. Any configuration attempting to enable matching in production fails closed at startup (`ConfigurationError` / `ValueError`).
> 
> While face detection (localized bounding box detection for authorized forensic blur/redaction) and synthetic test harness matching are technically verified, live operational biometric matching against campus populations is denied pending independent external civil liberties review, published judicial/statutory warrants, and institutional executive sign-off.

---

## 1. Purpose Limitation & Prohibition of Mass Surveillance (Phases 71 & 72)

### 1.1 Strict Purpose Scoping
Biometric processing in E-WITNESS is strictly restricted by software enums, database check constraints, and API validators to the following 4 narrow operational purposes:
- `explicit_consent_reference_enrollment`: Explicit, voluntary subject enrollment for authorized verification.
- `authorized_investigative_manual_review`: Forensic inspection of specific, lawfully isolated evidence attachments under approved warrants.
- `privacy_redaction_blurring`: Automated face localization to obscure identities and protect bystander privacy prior to evidence disclosure.
- `testing_synthetic_benchmark`: Evaluation of algorithms using synthetic, de-identified benchmarking fixtures.

### 1.2 Categorically Prohibited Operations
The system enforces technical and database-level prohibitions against:
1. `mass_surveillance_crowd_scanning`: Unrestricted or wide-area camera stream analysis.
2. `autonomous_punitive_decision`: Making disciplinary, academic, legal, or employment decisions based on AI scores.
3. `emotion_or_sentiment_inference`: Detecting internal mental states, micro-expressions, deceit, or agitation.
4. `demographic_profiling`: Inferring race, ethnicity, gender, sexual orientation, or religion from facial geometry.
5. `covert_unauthorized_tracking`: Re-identifying individuals across multiple camera locations without consent or warrants.

Attempting to register or execute any operation with a prohibited purpose fails closed immediately (`BiometricGovernanceError` / `422 Unprocessable Entity`).

---

## 2. Consent Lifecycle & Lawful Basis (Phase 73)

### 2.1 Lawful Basis Alignment
Biometric data processing requires an explicit lawful basis recorded in `biometric_governance_records`:
- `explicit_consent` (GDPR Art. 9(2)(a)): Freely given, specific, informed, and unambiguous subject consent.
- `statutory_legal_obligation` (GDPR Art. 9(2)(b)): Legally mandated evidence preservation.
- `substantial_public_interest` (GDPR Art. 9(2)(g)): Severe campus safety emergency with authorized judicial oversight.
- `research_benchmark_exempt`: Pure synthetic benchmark testing.

### 2.2 Cascading Consent Revocation
When a subject exercises their right to withdraw consent (`POST /api/v1/biometrics/governance/{id}/withdraw`):
1. The governance record status transitions immediately to `withdrawn`.
2. All linked reference records in `biometric_references` transition to `revoked`.
3. Encrypted template payloads stored in `encrypted_template` are zeroized and permanently wiped from the database.
4. Future matching or detection requests referencing this governance record fail closed with `CONSENT_WITHDRAWN`.

---

## 3. Template Protection & Cryptographic Key Management (Phase 78)

### 3.1 Authenticated Encryption at Rest
Biometric templates are never persisted in plaintext. Templates are protected using AES-256-GCM authenticated symmetric encryption:
- **Algorithm**: `AES-256-GCM` via standard `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
- **Envelope Format**: `v1:<key_id>:<base64(12_byte_nonce + ciphertext + 16_byte_tag)>`.
- **Cryptographic Binding**: Associated Authenticated Data (AAD) binds the envelope version and `key_id` to prevent key substitution attacks.

### 3.2 Key Ring Management & Lifecycle (`BiometricKeyManager`)
Key lifecycle transitions follow a secure finite state machine:
- `ACTIVE`: Key currently used for encrypting new biometric templates.
- `ROTATED`: Historic key that can decrypt existing templates, but is not used for new encryptions.
- `REVOKED`: Invalidated key. Any decryption attempt against a revoked key **fails closed immediately** (`BiometricKeyRevokedError`).

### 3.3 Zero Raw Template Leakage
- Raw templates, feature vectors, and private key bytes are excluded from string representations (`__repr__` / `__str__`).
- REST API read schemas (`BiometricReferenceRead`, `BiometricVerificationReviewRead`) strictly omit encrypted or raw template attributes.
- Audit event payloads log only cryptographic hashes (SHA-256 digests) and record identifiers.

---

## 4. Accuracy, Uncertainty Bands & Decision Boundaries (Phases 76 & 77)

### 4.1 Similarity Score as Advisory Metric Only
In accordance with non-negotiable safety principles:
- **A similarity score is an advisory metric, never proof of identity.**
- All matching outputs attach the mandatory statutory disclaimer:  
  `BIOMETRIC_MATCHING_ADVISORY_DISCLAIMER`.

### 4.2 Non-Binary Uncertainty Band $[0.60, 0.85]$
Binary match/non-match classification is strictly forbidden. The system enforces an explicit 3-zone decision boundary:
1. **$S < 0.60$**: `NON_MATCH_CANDIDATE` — Advisory non-match.
2. **$0.60 \le S < 0.85$**: `INCONCLUSIVE_UNCERTAIN` — Ambiguous model outcome; must never be forced into a match or non-match.
3. **$S \ge 0.85$**: `MATCH_CANDIDATE` — Advisory candidate match requiring mandatory independent human review.

---

## 5. Demographic Fairness & Synthetic Benchmark Disclaimers (Phase 79)

### 5.1 Subgroup Disparity Analysis
The evaluation module (`ai_services/face_matching/evaluation.py`) measures False Match Rate (FMR) and False Non-Match Rate (FNMR) across demographic or synthetic cohorts, calculating the maximum disparity ratio:
$$\text{Disparity Ratio} = \frac{\max(FMR_i)}{\min(FMR_j)}$$

### 5.2 Mandatory Synthetic Test Disclaimers
Because real campus biometric datasets cannot ethically or legally be assembled for test fixtures:
- All benchmark metrics are calculated using deterministic synthetic pseudo-random vectors.
- Every report generated attaches the hardcoded statutory limitation:  
  `SYNTHETIC_BENCHMARK_DISCLAIMER`: *"Evaluations performed on synthetic benchmarks do NOT validate real-world operational performance across diverse human demographics."*

---

## 6. Presentation Attack Detection (PAD) Simulation (Phase 79)

### 6.1 ISO/IEC 30107-3 Performance Metrics
The system benchmarks biometric spoof resilience using standard error rates:
- **APCER** (Attack Presentation Classification Error Rate): Proportion of spoof attacks (e.g. 2D photo, mask, replay) incorrectly accepted as bona fide presentations.
- **BPCER** (Bona Fide Presentation Classification Error Rate): Proportion of legitimate presentations incorrectly flagged as attacks.

---

## 7. Input Quality Assessment Guardrails (Phase 77)

### 7.1 Pre-Matching Verification (`assess_face_image_quality`)
Before any feature extraction or matching is attempted, input image payloads must pass:
1. **Container & Header Validation**: Valid PNG, JPEG, or WebP magic bytes without header corruption.
2. **Spatial Resolution**: Minimum dimensions of $64 \times 64$ pixels. Low-resolution images are rejected (`LOW_RESOLUTION`).
3. **Contrast / Luminance Variance**: Rejects blank, pitch-black, or washed-out images with payload variance below 5.0 (`POOR_CONTRAST`).
4. **Audit Logging**: Quality check failures trigger `BIOMETRIC_QUALITY_FAILED` audit events.

---

## 8. Human Oversight & Independent Verification Workflow (Phase 77)

### 8.1 Qualified Human Reviewer Role
- Automated matching never produces a final identity determination.
- All candidate matching results produce a `BiometricVerificationReview` persistence record.
- Only authorized users with `BIOMETRIC_VERIFICATION_REVIEW` permission (`INVESTIGATOR`, `DEPT_ADMIN`, `SUPER_ADMIN`) may record determinations.

### 8.2 Mandatory Override Justification
- If a human reviewer's verdict contradicts the automated candidate result (e.g., automated candidate was `NON_MATCH_CANDIDATE` but reviewer confirms `VERIFIED_MATCH`, or reviewer selects `REJECTED_OVERRIDE`):
  - The `is_override` flag is set to `True`.
  - A non-empty, detailed `override_reason` is **strictly enforced** by Pydantic and database constraints.
  - An immutable `BIOMETRIC_VERIFICATION_RECORDED` audit event is dispatched.

---

## 9. Tenant & Department Data Isolation

### 9.1 Multi-Tenant Boundaries
- All biometric tables (`biometric_governance_records`, `biometric_references`, `biometric_verification_reviews`) carry indexed `tenant_id` and `department_id` foreign keys.
- Department administrators and investigators are strictly scoped to records within their assigned department.
- Cross-department or cross-tenant query attempts return `ResourceNotFoundError` (`404 Not Found`) to prevent information enumeration.

---

## 10. Fail-Closed Error Handling & Configuration Posture

### 10.1 Default Disabled Posture
- `BIOMETRIC_ANALYSIS_ENABLED = False` by default.
- `BIOMETRIC_DETECTION_ENABLED = False` by default.
- `BIOMETRIC_MATCHING_ENABLED = False` by default.
- `BIOMETRIC_PROVIDER = "disabled"` by default.

### 10.2 Production Lock
- In `backend/app/config/settings.py`, startup validation asserts that `BIOMETRIC_MATCHING_ENABLED` cannot be `True` when `ENVIRONMENT == "production"`. Any startup attempt in production with matching enabled raises a fatal configuration exception.

---

## 11. Retention Periods & Purge Automation

### 11.1 Retention Governance
- Default retention: 90 days.
- Maximum permitted retention: 365 days (enforced by SQL check constraint `ck_biometric_governance_retention_days`).
- Enrolled references automatically calculate `retention_expires_at` based on approved governance records.
- Expired references transition to `expired` status and their template ciphertexts are purged from disk/database.

---

## 12. Security Audit Trail & Non-Repudiation

### 12.1 Dedicated Audit Actions
The following security audit events are permanently recorded in `security_audit_events`:
- `BIOMETRIC_MATCHING_EXECUTED`: Logged on every matching execution with probe hash and similarity score.
- `BIOMETRIC_QUALITY_FAILED`: Logged when an image fails resolution or contrast thresholds.
- `BIOMETRIC_VERIFICATION_RECORDED`: Logged when an authorized human records or overrides a candidate decision.
- `BIOMETRIC_KEY_ACCESSED`: Logged when a template encryption key is retrieved for template decryption.
- `BIOMETRIC_KEY_ROTATED`: Logged when key rotation occurs.

All audit entries include actor ID, role, department, timestamp, outcome, and client IP.

---

## 13. Executive Release Gates & Final Sign-Off

| Gate ID | Audit Criterion | Technical Verification | Release Status |
|:---|:---|:---|:---:|
| **GATE-01** | Purpose Limitation & Prohibited Uses | Verified in core domain & schemas | **PASS** |
| **GATE-02** | Consent Lifecycle & Revocation | Verified cascading purge on withdrawal | **PASS** |
| **GATE-03** | Template AES-256-GCM Encryption | Verified key rotation, envelope format & fail-closed revocation | **PASS** |
| **GATE-04** | Non-Binary Uncertainty Band | Verified [0.60, 0.85] inconclusive handling | **PASS** |
| **GATE-05** | Image Quality Guardrails | Verified resolution & contrast checks | **PASS** |
| **GATE-06** | Human Oversight & Override Workflow | Verified BiometricVerificationReview & mandatory reason | **PASS** |
| **GATE-07** | Reproducible Evaluation Suite | Verified FMR, FNMR, FTA, DET & PAD calculations | **PASS** |
| **GATE-08** | Multi-Tenant Data Isolation | Verified department foreign keys & query boundaries | **PASS** |
| **GATE-09** | Production Matching Lockout | Verified fail-closed startup validation | **PASS** |
| **GATE-10** | **Operational Production Matching Authorization** | **External judicial/statutory warrants not provided** | **NO-GO** |

### Final Operational Release Status
- **Face Detection (Privacy Blurring / Localization)**: **CONDITIONAL GO** (under approved governance).
- **Biometric Face Matching / Identification**: **MANDATORY PRODUCTION NO-GO**.
