# Secret exposure audit

Audited on 2026-09-22. **No exposed credentials were detected in the inspected public surfaces. No keys were rotated**, because the checks found no confirmed exposure.

| Surface | Checks and result |
| --- | --- |
| Public Git history | All 7 commits and 130 unique blobs; 40 current/retained historical credentials compared locally, plus Gitleaks 8.30.1. Zero findings. |
| Releases and packages | All 25 GitHub release assets, six published crate versions, and the exact uploaded Honeycomb 0.1.0 and 0.1.2 packages. Nested contents scanned; zero findings. |
| GitHub Actions | All 30 retrievable artifacts and seven run logs. Zero findings or unavailable objects. |
| Frontend | 18 live resources, 30 historical web blobs, and 50 unique uploaded files from all five READY Vercel deployments. Zero findings. Source-map/private-file probes returned 404. |
| Deployment storage | At the initial audit, all 26 objects tested denied anonymous access. Bucket public-access blocks are enabled, ACL is owner-only, ownership is enforced, and no public bucket policy exists. Available CloudTrail events show private creation and no later public ACL/policy change. |
| Other public material | Pending nonignored workspace files, public commit/issue/comment material, and the related Space Station PR2 change also passed. |

The frontend uses public table identifiers, `tingfrontendanalytics` and `tingfrontendevents`. Its source references only those two specific Vite configuration variables; no whole-environment spread was found. Ingestion credentials are supplied by the backend.

GitHub's built-in secret scanning was disabled at the initial audit. Secret scanning and push protection are now enabled, as recorded in [repository protection settings](github-secret-protection.json). The independent scans remain the evidence for the history audit; GitHub's asynchronous scan is not claimed complete. Credential comparisons stayed local; no secret values were submitted to search services or included in this report.

This is evidence of no detected exposure, not proof about every possible historical disclosure. Deleted/unretrievable artifacts and separately shared signed URLs are outside the verified scope. Vercel's authenticated file API exposed uploaded source and pre-existing `dist`, but not final protected remote build bytes; it did not return earlier build-environment values. No protection settings or tokens were changed to obtain access.

The subsequently uploaded Honeycomb 0.1.2 archive also passed a fresh local comparison against 40 known credentials and token/key patterns across all 26 archive objects. Its temporary upload-credential object was removed, including all versions, and the packaging scratch directory was deleted. The immutable archive hash and result are recorded in the [0.1.2 package audit](honeycomb-012-secret-audit.json).

Detailed scope: [audit results](secret-audit-results.json), [frontend audit](frontend-secrets-audit.json), and [authenticated frontend history](frontend-authenticated-history-audit.json).
