<!--
File: docs/operations/analytics-prod-scoped-operations.md
Purpose: Permanent, scoped Analytics PROD remote execution policy.
Related: deployment/analytics_prod_scoped_ops.py,
         deployment/analytics_prod_ops_install.py,
         deployment/analytics_prod_pg_readonly.py,
         AGENTS.md, docs/adr/0012-direct-dev-prod-delivery.md.
-->

# Analytics PROD: scoped remote operations

## Owner intent

The Product Owner wants ChatGPT to run recurrent PROD scripts directly,
without copying sudo commands every time. A blanket passwordless root
shell, user-controlled script execution, unrestricted PostgreSQL role or
Docker socket access would also grant the ability to destroy production
data and bypass release authorization. Those permissions are not granted.

Instead, one initial bootstrap installs exact root-owned Python sources
and fixed sudoers rules for the existing trusthansen remote connection.

## Supported commands

These remain available after reboot:

    sudo -n /usr/bin/python3 -I -B /usr/local/libexec/omnilyzer-analytics-prod-ops.py pg-audit
    sudo -n /usr/bin/python3 -I -B /usr/local/libexec/omnilyzer-analytics-prod-ops.py runtime-status

The PG audit reads only PostgreSQL16 catalog/HBA metadata inside a
transaction explicitly declared READ ONLY, omitting password verifiers.
The runtime status checks only Nginx, PostgreSQL, the dedicated user990
manager, rootful Docker masks and fixed private localhost listeners.

Both operations reject unrecognized arguments, callers, hosts, and
unexpected root-owned source changes. No arbitrary SQL, paths, Python
scripts, shell, package management, container modifications or Nginx
route edits can be requested.

## One-time authorized installation

Review the three complete repository files and their SHA256 signatures.
Stage the installer and fixed helper files in the existing owner home
as mode0600; the installer checks the exact reviewed bytes of each.
Copy the reviewed installer to a new root-owned, mode0500 file named
/usr/local/sbin/omnilyzer-analytics-prod-ops-install-20261117.
Check its SHA256 before execution and invoke once with --install.

The installer runs local visudo validation BEFORE activating the sudo
rule, creates root-owned read-only operation code via exclusive new-file
creation, and writes the exact sudoers rule LAST. If a partial error
occurs, do not retry blindly; first inspect the actual state.

Privileged destinations:

- /usr/local/libexec/omnilyzer-analytics-prod-ops.py
- /usr/local/libexec/omnilyzer-analytics-prod-pg-readonly.py
- /etc/sudoers.d/94-omnilyzer-analytics-prod-ops

## Future scripts and release operations

Ordinary non-root scripts already run through the existing remote account.
For future scripts requiring root, add only specifically reviewed
product operations, with their own fixed arguments, allowed data
boundaries and release authorization. The current sudo rule intentionally
does not allow arbitrary scripts. The helper may not be replaced by
changing files in Git or the owner's home.

Future release operations must preserve original signed Task013/014 OCI
verification, explicit owner authorization, no DEV credential reuse,
production tenant/RLS isolation, immutable installed code and rollback.
The existing DEV executor is bound to UID991 and DEV-specific paths and
must never be invoked on PROD. Disabled legacy prod.json remains inert.
No permanent staging server is necessary.

## Revocation

The owner can revoke precisely the scope by removing only
/etc/sudoers.d/94-omnilyzer-analytics-prod-ops from an authorized root
terminal and verifying sudoers syntax. Leave root-owned code inert for
forensic purposes if a release investigation is ongoing.
