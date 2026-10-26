# E-WITNESS — BATCH 11, GROUP 02: AI INFERENCE & WORKER SECURITY AUDIT
**Document Reference**: `artifacts/BATCH_11_AI_WORKER_SECURITY.md`  
**Execution Phase**: Phase 106 (Secure AI Inference, Jobs, Workers, Model Provenance & Biometric Prohibition)  
**Security Baseline**: Production Backend Readiness (Phases 01–110)  
**Status**: APPROVED & VERIFIED  

---

## 1. Executive Summary

Phase 106 establishes end-to-end security, input validation, execution constraints, and architectural governance for the E-WITNESS AI inference pipeline. The pipeline handles asynchronous video classification, candidate segment detection, violence/weapon indicator tagging, and human-review queue staging.

### Core Security Invariants Enforced
1. **Human-in-the-Loop Governance Invariant**: AI models identify and flag candidate segments strictly for authorized human review. AI models **must never determine guilt, independently establish that a crime occurred, or impose punishment**.
2. **Absolute Biometric Prohibition Invariant**: Real-time biometric face recognition and 1:N biometric matching are **strictly prohibited** by design and locked by runtime policy (`BIOMETRIC_MATCHING_ENABLED=False`). Any invocation of prohibited endpoints returns `403 Forbidden` (`BIOMETRIC_FEATURE_DISABLED`).
3. **Model Provenance & Path Traversal Immunity**: Model identifiers and versions are validated against an immutable registry (`APPROVED_AI_MODELS`). Any path traversal sequences (`..`, `/`, `\`), null bytes (`\x00`), or command injection characters trigger immediate rejection (`ValidationError` / `422 Unprocessable Entity`).
4. **Queue Concurrency & Quota Protection**: Duplicate active jobs for the same evidence item are blocked (`ConflictError` / `409 Conflict`), department concurrency quotas prevent resource starvation (`BusinessRuleError` / `422 Unprocessable Entity`), and execution timeouts (`TimeoutError` -> `RESOURCE_EXHAUSTED`) bound worker execution without infinite loops.
5. **Exception & Log Sanitization**: Worker failures sanitize internal error strings, stripping database credentials, storage keys, and file paths before saving to audit logs or database records.

---

## 2. Model Provenance & Registry Verification

### 2.1 Model Registry Architecture
All AI models deployed or requested within E-WITNESS must be registered in the immutable model registry defined in `backend/app/core/ai.py`:

```python
APPROVED_AI_MODELS: Final[dict[str, dict[str, Any]]] = {
    "violence-classifier": {
        "allowed_versions": ["1.0.0", "1.1.0"],
        "default_version": "1.0.0",
        "description": "Video violence and altercation candidate segment classifier",
        "human_review_required": True,
        "prohibited_for_biometrics": True,
    },
    "weapon-detector": {
        "allowed_versions": ["1.0.0"],
        "default_version": "1.0.0",
        "description": "Visual firearm and bladed weapon bounding detector",
        "human_review_required": True,
        "prohibited_for_biometrics": True,
    },
    "audio-threat-classifier": {
        "allowed_versions": ["1.0.0"],
        "default_version": "1.0.0",
        "description": "Acoustic gunshot and distress scream candidate classifier",
        "human_review_required": True,
        "prohibited_for_biometrics": True,
    },
}
```

### 2.2 Provenance Validation Function (`validate_model_provenance`)
Path traversal attacks and injection attempts are intercepted prior to job creation:

- **Traversal Patterns Detected**: `..`, `/`, `\`, `%2e%2e`, null bytes `\x00`, shell characters (`;`, `|`, `&`, `$`, `` ` ``, `<`, `>`).
- **Identifier Validation**: Must match regex `^[a-z0-9][a-z0-9_-]{1,63}$`.
- **Version Validation**: Must match semver regex `^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$`.
- **Registry Check**: Model name must exist in `APPROVED_AI_MODELS` and version must exist in `allowed_versions`.

### 2.3 Weight Integrity & Filesystem Containment (`PretrainedVideoClassifierProvider`)
The video classifier in `ai_services/violence_detection/classifier.py` enforces cryptographic integrity:
- **Base Directory Containment**: Model files must strictly reside within `allowed_base_dir` using `os.path.commonpath` verification. Symlinks pointing outside the base directory or relative traversals raise `ValueError("Model path traversal detected outside allowed directory")`.
- **SHA-256 Digest Verification**: If `expected_sha256` is provided, model weights are digested prior to loading. Corrupted or tampered weights raise `ValueError("Model weight integrity verification failed")`.

---

## 3. Asynchronous Job Queue Hardening & Concurrency Controls

### 3.1 Duplicate Job Prevention
Submitting multiple concurrent analysis jobs for the same piece of evidence creates race conditions and wastes compute resources.
- **Repository Check**: `ai_job_repo.get_active_job_for_evidence(evidence_id)` queries jobs with status `queued` or `running`.
- **Enforcement**: If an active job exists, `AIService.submit_analysis_job` immediately raises:
  `ConflictError("An active AI analysis job already exists for this evidence item.", code="ACTIVE_JOB_EXISTS")`.

### 3.2 Department Concurrency Quotas
To prevent single-tenant or single-department resource starvation:
- **Repository Check**: `ai_job_repo.count_active_for_department(department_id)` counts active jobs across the caller's department.
- **Enforcement**: If active jobs exceed `MAX_CONCURRENT_AI_JOBS_PER_DEPT` (default: 5), the service raises:
  `BusinessRuleError(..., code="AI_JOB_QUOTA_EXCEEDED")`.

### 3.3 Worker Execution Timeout & Error Sanitization
- **Timeout Bound**: Job execution is wrapped with `asyncio.wait_for(timeout=30.0)`. On expiry, the job status is set to `failed` with code `RESOURCE_EXHAUSTED`.
- **Error Sanitization**: Worker catches `Exception` and executes `_sanitize_error_message(str(e))`:
  - Strips PostgreSQL connection URIs, database passwords (`password=***`), file system root paths, and stack traces.
  - Emits security audit event `ai.job.execution_failed` with sanitized details.

---

## 4. Biometric Prohibition Enforcement

E-WITNESS strictly complies with criminal justice civil rights mandates prohibiting automated facial identification in criminal evidence processing:
- **Configuration**: `BIOMETRIC_MATCHING_ENABLED: bool = False` (locked in `backend/app/core/config.py`).
- **Endpoint Protection**: Biometric identification routes in `backend/app/api/v1/biometrics.py` verify this flag on entry:
  ```python
  if not settings.BIOMETRIC_MATCHING_ENABLED:
      raise HTTPException(
          status_code=status.HTTP_403_FORBIDDEN,
          detail="Automated biometric face matching is strictly prohibited by system governance policy.",
      )
  ```
- **Layer Boundary Test**: `tests/unit/ai/test_batch11_ai_security_and_provenance.py` includes `test_biometric_matching_strictly_disabled_in_production` to ensure the flag cannot be toggled in production environments.

---

## 5. Verification Test Matrix

All 17 Phase 106 security and provenance tests passed with zero failures:

| Test Identifier | Test Case Name | Target Component | Status |
|---|---|---|:---:|
| TC-106-01 | `test_model_provenance_validation_rejects_unapproved_model` | `validate_model_provenance()` | **PASS** |
| TC-106-02 | `test_model_provenance_validation_rejects_unapproved_version` | `validate_model_provenance()` | **PASS** |
| TC-106-03 | `test_model_provenance_validation_rejects_path_traversal[../../etc/passwd]` | Traversal Sanitizer | **PASS** |
| TC-106-04 | `test_model_provenance_validation_rejects_path_traversal[..\\..\\windows\\system32]` | Windows Traversal | **PASS** |
| TC-106-05 | `test_model_provenance_validation_rejects_path_traversal[models/violence-classifier]` | Subdirectory Traversal | **PASS** |
| TC-106-06 | `test_model_provenance_validation_rejects_path_traversal[classifier\x00extra]` | Null Byte Injection | **PASS** |
| TC-106-07 | `test_model_provenance_validation_rejects_path_traversal[violence;rm -rf /]` | Command Injection | **PASS** |
| TC-106-08 | `test_model_provenance_validation_rejects_path_traversal[violence\|cat /etc/shadow]` | Shell Pipe Injection | **PASS** |
| TC-106-09 | `test_ai_job_submit_request_schema_enforces_provenance` | `AIJobSubmitRequest` | **PASS** |
| TC-106-10 | `test_submit_analysis_job_duplicate_active_job_rejected` | `AIService.submit_analysis_job` | **PASS** |
| TC-106-11 | `test_submit_analysis_job_quota_exceeded_rejected` | `AIService.submit_analysis_job` | **PASS** |
| TC-106-12 | `test_execute_job_handles_timeout_cleanly` | `AIService._execute_job` | **PASS** |
| TC-106-13 | `test_execute_job_sanitizes_internal_error_messages` | `AIService._sanitize_error` | **PASS** |
| TC-106-14 | `test_classifier_weights_integrity_verification` | `PretrainedVideoClassifierProvider` | **PASS** |
| TC-106-15 | `test_classifier_weights_rejects_path_traversal` | `PretrainedVideoClassifierProvider` | **PASS** |
| TC-106-16 | `test_biometric_matching_strictly_disabled_in_production` | `Settings.BIOMETRIC_MATCHING_ENABLED` | **PASS** |
| TC-106-17 | `test_approved_model_registry_contains_mandatory_models` | `APPROVED_AI_MODELS` | **PASS** |

---

## 6. Residual Risk Assessment & Recommendations

1. **Model Weights Signing**: Future iterations should integrate Ed25519 or Cosign signature verification for model artifact tarballs loaded into production worker nodes.
2. **Worker Sandboxing**: Model inference workers should run in unprivileged, network-isolated container sandboxes without access to the primary relational database.
