# E-WITNESS — Biometric Privacy, Governance and Legal Feasibility Assessment
## Phase 71 & 72 Architectural and Legal Blueprint

**Document Reference**: `DOC-ARCH-BIO-001`  
**Classification**: PRIVILEGED TECHNICAL GOVERNANCE SPECIFICATION  
**Current Readiness State**: 🛑 **NO-GO (PRODUCTION ACTIVATION BLOCKED BY DEFAULT)**  
**Version**: 1.0.0 (October 14, 2026)  

---

## 1. Executive Summary and Foundational Principles

This assessment establishes the privacy, governance, legal feasibility, and technical bounds governing biometric capabilities in the E-WITNESS digital evidence and incident management platform.

### Non-Negotiable Core Invariants:
1. **Production Face Matching / Biometric Identification is Strictly Prohibited**: The system shall never perform automated open-universe face search, crowd identification, or one-to-many biometric matching against unconstrained video or arbitrary galleries in production.
2. **Face Detection is Decoupled from Identification**: Localizing a human face (drawing a bounding box) is strictly segregated from extracting biometric templates, computing embeddings, or asserting personal identity.
3. **No Autonomous Consequential Decisions**: Biometric analysis shall never determine guilt, justify disciplinary action, authorize employment sanctions, or independently alter legal custody.
4. **No Trait Inference**: Inferring emotions, sentiment, criminality, aggressiveness, trustworthiness, personality, or protected demographic traits from facial features is strictly banned.
5. **Fail-Closed Default**: In the absence of an affirmative, unexpired, and verified legal opinion, data protection impact assessment (DPIA), and administrative authorization, all biometric capabilities fail closed with immediate access denial.
6. **No Single-Consent Panacea**: Consent does NOT constitute a universal legal basis across all jurisdictions, particularly where academic, workplace, or custodial power imbalances negate freely given consent.

---

## 2. Purpose and Necessity Analysis

### 2.1 Legitimate Operational Purposes
Biometric technology carries severe privacy and civil liberties risks. Within E-WITNESS, biometric technology is justified only for three narrowly tailored, high-necessity functions:
1. **Privacy Redaction / Bystander Blurring (`PRIVACY_REDACTION_BLURRING`)**: Detecting face bounding boxes in incident video to automatically redact, pixelate, or obscure uninvolved bystanders, minors, victims, and witnesses before external export or public disclosure.
2. **Authorized Single-Case Reference Verification (`AUTHORIZED_INVESTIGATIVE_MANUAL_REVIEW`)**: Assisting an authorized investigator operating under a verified court order, legal warrant, or statutory mandate to confirm whether a specific single reference subject appears in designated operational evidence.
3. **Voluntary Informed-Consent Reference Enrollment (`EXPLICIT_CONSENT_REFERENCE_ENROLLMENT`)**: Allowing authorized individuals (e.g., campus safety officers, credentialed personnel) to voluntarily register an opaque reference template for personal access verification.

### 2.2 Less Intrusive Alternatives
Under the doctrine of data minimization (GDPR Art. 5(1)(c)), biometric processing is permissible only if less intrusive alternatives cannot achieve the legitimate objective:
- **Badge / Card Access Logs**: Sufficient for access control; preferred over facial recognition.
- **Multi-Factor Software Tokens**: Preferred for identity verification in digital systems.
- **Manual Human Review**: Review by trained forensic investigators using standard visual corroboration (clothing, badges, time, location, vehicle plates) without algorithmic biometric template extraction.
- **Manual Video Redaction**: Viable for short clips, but computationally assisted face *detection* (without identification) is necessary to ensure reliable privacy protection across large volumes of exported video.

---

## 3. Legal and Regulatory Feasibility Across Jurisdictions

Biometric data constitutes "special category" or sensitive personal data under global data protection frameworks. **Technical implementation alone does not establish a lawful basis. Prior to production activation in any tenant jurisdiction, qualified legal counsel must issue an affirmative written legal opinion.**

### 3.1 Applicable Statutory Frameworks
- **European Union General Data Protection Regulation (GDPR)**:
  - *Article 9(1)*: General prohibition on processing biometric data for the purpose of uniquely identifying a natural person.
  - *Article 9(2)* Exceptions: Explicit consent (Art. 9(2)(a)) or reasons of substantial public interest with statutory basis and safeguards (Art. 9(2)(g)). In employment and educational settings, the European Data Protection Board (EDPB) considers consent invalid due to power imbalances.
- **Illinois Biometric Information Privacy Act (BIPA, 740 ILCS 14/)**:
  - Requires written policy, retention schedule, informed written consent prior to capture, prohibition on sale or profiting, and strict storage standards matching general industry encryption.
- **Texas Capture or Use of Biometric Identifier Act (CUBI, Tex. Bus. & Com. Code § 503.001)**:
  - Requires consent, destruction within one year of purpose expiration, and strict disclosure bans.
- **California Consumer Privacy Act / CPRA (Cal. Civ. Code § 1798.100 et seq.)**:
  - Treats biometric information as "Sensitive Personal Information" subject to right to limit use and explicit disclosure obligations.
- **Family Educational Rights and Privacy Act (FERPA, 34 CFR Part 99)**:
  - Biometric records of students constitute personally identifiable educational records requiring explicit parental/eligible student consent for disclosure.
- **Criminal Justice Information Services (CJIS) Security Policy**:
  - Enforces strict tenant separation, audit logging, and encryption for law enforcement biometric data.

---

## 4. Data Flows, Minimization, and Cryptographic Protection

### 4.1 Data Categories and Collection
| Data Category | Purpose | Collection Point | Storage Standard |
| :--- | :--- | :--- | :--- |
| **Video Frames / Image Bytes** | Bounding box detection | Ephemeral in-memory | Never persisted; scrubbed immediately after inference |
| **Bounding Box Coordinates** | Redaction / Localization | `[ymin, xmin, ymax, xmax]` | Stored in JSON metadata |
| **Opaque Reference ID** | Registry indexing | System-generated UUID/hex | Plaintext index (e.g., `REF-BIO-4A7F...`) |
| **Template SHA-256 Digest** | Integrity verification | 64-char hex string | Plaintext check column |
| **Biometric Template / Embedding** | Single-subject comparison | Encrypted buffer | KMS/Fernet ciphertext at rest; **never stored in plaintext** |

### 4.2 Strict Processing Isolation
- **No Third-Party Transmission**: Biometric data, images, and templates shall NEVER be transmitted to third-party cloud face-analysis APIs (e.g., AWS Rekognition, Azure Face API, Google Cloud Vision). All detection executes locally in sandboxed, network-isolated compute.
- **No Model Downloads at Runtime**: Weights and classifiers must be locally staged, cryptographically verified by SHA-256 digest, and baked into the deployment image.

---

## 5. Risk Assessment and Algorithmic Harms

1. **Disparate Demographic Performance**:
   - Commercial and academic face-analysis algorithms historically exhibit higher false positive rates and error disparities for individuals with darker skin tones, women, and young adults (NIST FRVT reports).
   - *Mitigation*: Face detection operates at conservative, balanced confidence thresholds; zero automated identity assertions; human forensic verification mandatory.
2. **Chilling Effect and Assembly Suppression**:
   - Surveillance or face detection at campus gatherings or protests suppresses First Amendment speech and academic freedom.
   - *Mitigation*: Biometric analysis is strictly prohibited on general crowd footage or public area monitoring.
3. **Function Creep**:
   - Expanding from redacting bystanders to tracking individuals across cameras.
   - *Mitigation*: Hard architectural boundary separating face detection (bounding box) from template generation and matching. Matching engine is disabled in code and configuration.

---

## 6. Governance, Consent, and Notice Lifecycle

### 6.1 Versioned Notices and Clear Opt-In
- When explicit consent is the designated legal basis, subjects must be presented with a versioned plain-language notice (`notice_version`, e.g., `1.0.0`) detailing:
  - Exact purpose of processing.
  - Categories of data collected.
  - Retention duration (maximum 90 days default).
  - Explicit right to withdraw consent at any time without adverse academic or employment consequences.

### 6.2 Withdrawal Handling and Propagation
- Upon receipt of consent withdrawal:
  1. `BiometricGovernanceRecord` transitions immediately to `status = 'revoked'`, `consent_status = 'withdrawn'`.
  2. The withdrawal timestamp (`withdrawn_at`) and actor are immutably logged to the audit ledger.
  3. All associated active `BiometricReference` records are immediately revoked and their encrypted templates permanently wiped.
  4. Future analysis requests referencing the withdrawn governance record fail closed.

---

## 7. Operational Readiness Checklist & Documented NO-GO State

A tenant or system environment is in a strict **NO-GO** state unless ALL eight prerequisites are affirmatively verified and documented:

| # | Prerequisite Item | Verification Standard | Current State |
| :-: | :--- | :--- | :-: |
| 1 | **Qualified Legal Opinion** | Written memorandum from qualified legal counsel approving specific use case under tenant jurisdiction | 🛑 **NO-GO** (Pending legal review) |
| 2 | **Data Protection Impact Assessment (DPIA)** | Approved DPIA documenting necessity, proportionality, and mitigations | 🛑 **NO-GO** (Pending DPIA) |
| 3 | **Published Privacy Policy** | Publicly accessible policy detailing biometric retention, notice, and deletion | 🛑 **NO-GO** (Pending publication) |
| 4 | **Executive Sign-Off** | Institutional head / Chief Legal Officer signature authorizing capability | 🛑 **NO-GO** (Pending executive sign-off) |
| 5 | **Security Architecture Review** | Verification of encryption at rest, memory scrubbing, and audit integrity | 🟢 **PASS** (Architecture verified) |
| 6 | **Tenant Admin Opt-In** | Explicit enablement by tenant administrator (`BIOMETRIC_ANALYSIS_ENABLED=True`) | 🛑 **NO-GO** (Disabled by default) |
| 7 | **Production Matching Lock** | Verification that `BIOMETRIC_MATCHING_ENABLED=False` in production environment | 🟢 **PASS** (Hardcoded check enforced) |
| 8 | **Subject Consent / Legal Warrant** | Active, unrevoked consent record or court-ordered warrant reference | 🛑 **NO-GO** (Enforced per transaction) |

### Formal Verdict:
**Overall System State**: 🛑 **NO-GO**  
*Biometric processing remains administratively and technically locked in production until institutional approvals are formally certified.*
