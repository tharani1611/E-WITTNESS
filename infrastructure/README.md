# E-WITNESS Infrastructure Definitions (Reserved)

This directory is reserved for Infrastructure-as-Code (IaC), network policies, object-storage bucket policies, and database provisioning templates scheduled for later phases of the 120-phase master roadmap.

## Architectural Expectations

- Private network segmentation for PostgreSQL, Redis, and S3-compatible evidence storage buckets.
- Object storage bucket policies must block public access (`BlockPublicAcls`, `BlockPublicPolicy`, `IgnorePublicAcls`, `RestrictPublicBuckets`) and enforce encryption at rest.
