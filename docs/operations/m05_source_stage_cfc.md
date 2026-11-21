# M05 Task14B P0 - PR316 exact immutable source-stage handover

Status: DRAFT REVIEW ONLY / ROOT NOT EXECUTED / NO LIVE DEV CHANGE / NO PROD.

- Signed Analytics0.16.0 remains green and private ready HTTP200.
- Current immutable root source: 330f3255f0067b9ddbe30d50466830bd71a55a11.
- Target reviewed app source: cfc274117fed99e01c24fda62ab0065170f3314a (draft PR316).
- Existing root-owned immutable source contains 76 root:root 0644 files and 9 root:root 0755 directories. Exact Git source diff requires ONLY 2 runtime replacements: analytics_executor.py and analytics_route_journal.py. Other 74 files unchanged.
- Destination new root SHA-named directory and the exclusive staging directory are ABSENT.
- New root-source-stage-reviewed.py reuses the original, protected, root-only installer at /opt/omnilyzer/deployment/.m05-ordinary-reviewed-source-f4a69fc9a3afa361255365ed6d19419bcb58c1c8 and original audited stage+atomic rename functions. The 76-file runtime excludes the source-installer module, so it must not be imported from the runtime source.
- New operator installation destination: /usr/local/libexec/omnilyzer-m05-ordinary-source-stage-cfc.py, root:root mode0500 and one link. No existing file is overwritten.
- Exact root operator source SHA256 e6727658ea1f815eeac39ea817304e1d329767b83eeafa25a101d04b4f3a3847.
- Exact canonical 76-file manifest SHA256 f931fcd93d0a36245a3b7c66482040e0b27483c4254764cd95299a9d6be13f32 (user 1005:1005 mode0400, one link).
- Reviewed replacements:
  - deployment/analytics_executor.py SHA256 34de557ca2d5e63adb6cc5c18c827dd5f266040e699525670d21c9667b84f5ff
  - deployment/analytics_route_journal.py SHA256 d6163f72d113b9c64765c6390923aab93e1d41408883f99d595f56fbaad10374
- Root operator has only --check (read-only) and --stage (one-time new immutable 76-file source creation), with original root-only identity and exact hash checks. No broker/executor socket, service, Docker, OCI image, replay/JTI, database, Task014 dispatch, OAT certificate or PROD mutation.
- The unprivileged 76-file source/2-replacement identity test PASSED, but positive native-root --check and --stage were NOT performed; UID1005 cannot inspect the original root0500 installer code.
- The separate target source approval remains UNSIGNED. Draft handover does not authorize a release or privileged operation.

## Remaining gates

1. Independent M04 approval of exact root-operator source SHA256, reviewed replacement hashes and existing protected installer import boundary.
2. Native owner-root verify exact operator and source approval, then read-only --check. No root --stage before M04 approval.
3. On approved source-stage success, separately prepare the legacy OAT root 0440 certificate, protected source config/systemd switch and rollback plan; executor/socket are currently failed from Task014 #44890393889 and must not simply be reset.
4. Only after actual attested UID991 recovery and stable signed0.16.0 may one fresh signed0.16.1 Task014 run/JTI be dispatched. Previously failed run is consumed. PROD unchanged.
