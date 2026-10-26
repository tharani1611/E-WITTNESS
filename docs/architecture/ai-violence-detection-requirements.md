# E-WITNESS AI Video Analysis Subsystem — Problem Definition & Requirements
## Phase 61: Intended Use, Prohibited Uses, Governance Boundaries & Measurable Requirements

**Document Version**: 1.0.0  
**Status**: APPROVED & ACTIVE  
**Security Classification**: CONFIDENTIAL — INTERNAL COMPLIANCE  
**Module**: `ai_services/violence_detection`  

---

## 1. Problem Definition & Operational Context

Campus security and student conduct investigations frequently involve hours of surveillance and body-worn camera footage. Manual review of lengthy recordings creates severe investigative bottlenecks, causes reviewer cognitive fatigue, and delays responses to critical safety incidents.

The E-WITNESS AI Video Analysis Subsystem is designed as an **advisory decision-support tool** to help authorized human investigators prioritize potentially relevant segments of lengthy video recordings. It does **not** make autonomous decisions, replace human review, or determine evidentiary truth.

---

## 2. Intended Use

The E-WITNESS violence-detection subsystem is authorized strictly for the following functions:

1. **Investigative Prioritization**: Assist trained human investigators in locating potential segments of physical altercations or safety hazards in authorized evidence recordings.
2. **Reviewer Decision Support**: Surface candidate time intervals and probabilistic scores to reduce the time required to review lengthy, mostly inactive video files.
3. **Traceable Preprocessing**: Extract and log reproducible video container metadata (resolution, frame rate, duration, codecs) to support forensic verification.
4. **Governed Dataset Benchmarking**: Validate candidate model behaviors exclusively against registered, licensed, and consent-verified benchmark datasets.
5. **Auditable Lifecycle Tracking**: Ensure all analysis requests, model versions, configurations, and job executions are immutably logged in the E-WITNESS security audit ledger.

---

## 3. Explicitly Prohibited Uses & Guardrails

The E-WITNESS system strictly prohibits the following uses. Any attempt to configure or operate the system in violation of these rules is a critical security and policy violation:

1. **NO Autonomous Guilt Determination**: The system shall **never** determine that an individual committed violence or is guilty of a violation, misconduct, or crime.
2. **NO Automated Punishment or Disciplinary Action**: The system shall **never** trigger sanctions, disciplinary actions, account suspensions, campus bans, or law enforcement referrals without independent human investigation and legal due process.
3. **NO Evidentiary Truth Claims**: Model scores and candidate detections are probabilistic hypotheses; they are **never** authoritative evidence of facts.
4. **NO Identity, Demographic, or Biometric Profiling**: The model shall **never** classify individuals as violent or suspect based on race, ethnicity, gender, clothing, appearance, disability, or demographic traits. Facial recognition and biometric identity tracking are explicitly prohibited.
5. **NO Unvalidated or Hidden Surveillance**: The system shall **never** perform live, continuous, covert, or unauthorized mass surveillance on university premises.
6. **NO Unreviewed Downstream Actions**: All model outputs must be explicitly confirmed, rejected, or modified by a trained human reviewer before entering an incident case file.

---

## 4. Measurable Technical & Operational Requirements

### 4.1 Video Input & Resource Constraints
| Requirement ID | Parameter | Limit / Specification | Enforcement Mechanism |
| :--- | :--- | :--- | :--- |
| `REQ-AI-001` | Supported Containers | `video/mp4`, `video/webm` | Signature inspection & MIME allowlist |
| `REQ-AI-002` | Max Video Duration | **600 seconds (10 minutes)** per clip | Container metadata validation |
| `REQ-AI-003` | Max File Size | **250 MB** per evidence file | Bounded stream & storage check |
| `REQ-AI-004` | Min Resolution | **128 x 128 pixels** | Metadata parsing & decoder validation |
| `REQ-AI-005` | Max Resolution | **1920 x 1080 pixels (1080p)** | Rejection before memory allocation |
| `REQ-AI-006` | Max Execution Time | **120 seconds** per analysis job | Async worker timeout & cancellation |
| `REQ-AI-007` | Max Memory Allocation | **1.5 GB** per worker task | Bounded chunking & frame buffers |

### 4.2 Metadata & Preprocessing Reproducibility
| Requirement ID | Description | Specification |
| :--- | :--- | :--- |
| `REQ-AI-010` | Container Parsing | Must extract duration, dimensions, FPS, frame count, audio presence, and codecs without shell injection or external binary dependencies. |
| `REQ-AI-011` | Deterministic Sampling | Given identical source video bytes and `SamplingConfig`, sampling must produce identical frame indices, timestamps, and normalization tensors. |
| `REQ-AI-012` | Preprocessing Traceability | Every preprocessed output must record `sampling_config_version` and a SHA-256 digest of the sampled sequence. |
| `REQ-AI-013` | Corrupted Input Handling | Corrupted, zero-byte, truncated, or malformed containers must fail fast with sanitized, structured error categories. |

### 4.3 Model Interface & Governance
| Requirement ID | Description | Specification |
| :--- | :--- | :--- |
| `REQ-AI-020` | Stable Interface | Model execution must sit behind `VideoClassifierProtocol`, decoupling application services from underlying model architectures (VideoMAE, R(2+1)D, etc.). |
| `REQ-AI-021` | Fail-Safe Availability | When model weights, GPU runtime, or required packages are missing, the system must report `status="model_unavailable"` and raise controlled errors. Fabricating scores or using mocks in production is strictly prohibited. |
| `REQ-AI-022` | Output Schema | Output must return typed probabilities, predicted labels, execution latency, model version, and explicit disclaimers that scores are uncalibrated and advisory. |

### 4.4 Dataset Governance (Phase 62)
| Requirement ID | Description | Specification |
| :--- | :--- | :--- |
| `REQ-AI-030` | Provenance Verification | All datasets must record provenance, provider, acquisition date, license ID, and consent status before ingestion. |
| `REQ-AI-031` | License Filtering | Datasets with unknown, unapproved, or non-commercial licenses (for operational deployments) must be rejected. |
| `REQ-AI-032` | Manifest Digest Integrity | Dataset manifests must be cryptographically hashed (SHA-256) and validated before approval. |
| `REQ-AI-033` | Operational Separation | Operational case evidence shall **never** be automatically converted into training or evaluation datasets. |

### 4.5 Asynchronous Processing & Security (Phase 65)
| Requirement ID | Description | Specification |
| :--- | :--- | :--- |
| `REQ-AI-040` | Asynchronous Execution | Video analysis must run asynchronously; API calls must return immediately with a job ID and HTTP 202/201. |
| `REQ-AI-041` | Typed State Machine | Jobs transition strictly across `QUEUED` $\rightarrow$ `RUNNING` $\rightarrow$ `SUCCEEDED` / `FAILED` / `CANCELLED`. Terminal states cannot be overwritten. |
| `REQ-AI-042` | Tenant/Department Scoping | Jobs inherit the department of the source incident. Cross-department access returns HTTP 404. |
| `REQ-AI-043` | Bounded Retries | Transient failures retry up to 3 times with exponential backoff. Permanent validation failures fail immediately without retry. |
| `REQ-AI-044` | Audit Trail | Job submission, cancellation, success, and failure emit security audit events into the immutable ledger. |

---

## 5. Human-in-the-Loop Safeguards (Mandatory)

1. **Mandatory Advisory Banner**: Every user interface and API response delivering AI analysis results shall include the legal disclaimer:
   > *"AI-generated outputs are probabilistic and advisory. They do NOT constitute verified evidence, legal truth, or an autonomous finding of misconduct. Mandatory independent review by an authorized human investigator is required."*
2. **Reviewer Attribution**: Any inclusion of AI-assisted observations into a formal incident report must record the human investigator who reviewed and ratified the observation.
