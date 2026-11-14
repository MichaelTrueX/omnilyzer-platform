# Shared identity Chromium checkpoint, 29 October 2026

**Status: isolated QA PASS, not a production release or complete LC1 browser acceptance.**

Original Omnilyzer identity BFF draft #243 verifies the real temporary Keycloak 26.7.2 HTTPS signed callback and issues a digest-only session to the restricted S03 33-table production-shaped PostgreSQL16 database for a *fictional* adult test admission. A separate real Django PostgreSQL session database stores the platform identity.

The new optional QA helper `services/identity/tests/qa_s01_browser_gate.py` was exercised locally against the exact compiled S01 draft PR #243 HEAD `5730b9edbf7adce3d2e920f2f20a65d29baeae1c`. Playwright Chromium carried the actual secure Django session cookie into the S01 UI; each GET `/auth/session` was answered by a **fresh Django test client querying the actual PostgreSQL identity session**, not an `authenticated:true` stub.

**Observed PASS:** signed Keycloak login -> persistent Django identity session -> Chromium S01 authenticated Account session controls -> protected `/api/*` deliberately held HTTP503. The Keycloak refresh operation rotated the S03 cookie. After Django logout and S03 digest revocation, Chromium carrying the previous identity cookie received `authenticated:false`, showed `Sign in to study`, and made zero private API requests. No browser script errors; disposable S03 and identity PostgreSQL data destroyed.

The caller integration for this helper was tested in a temporary local modification of `run_keycloak_provider_interop_qa.py`, but is **not yet committed** into the draft. To reproduce, install Python `playwright==1.56.0` in a QA-only virtual environment, build S01 with `npm run build:private-bff-native`, and call `qa_s01_browser_gate.verify(django_client)` after the validated callback and `verify(django_client,authenticated=False,old_cookies=saved)` after logout, while the test PostgreSQL remains available. The helper requires `S01_QA_PRIVATE_BUILD_ROOT` to point at `dist-private-bff-candidate` and uses only loopback/browser interceptions.

**Not established:** S01's seven saved activities and eleven questions under the **same** real Keycloak-issued opaque S03 learner cookie. They passed separately in the current fresh and reused S03 Chromium test fixtures, which use an explicitly synthetic positive platform session. A joined true lesson test and real verified adult/guardian admission, domain TLS, operational secrets and Product Owner GO remain required. No main merge, live provisioning or production changes.
