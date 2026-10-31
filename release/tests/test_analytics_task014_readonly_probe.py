"""Offline boundary tests for the fixed-release read-only Analytics CI probe."""
from contextlib import redirect_stdout
import base64
import hashlib
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from release import analytics_task014_readonly_probe as probe
from release.tests.test_private_zot_auth_probe import ENVIRONMENT, NOW, synthetic_jwt


class ReadonlyAnalyticsProbeTests(unittest.TestCase):
    """Check independent failures, exact read targets, private cleanup and redaction."""
    def exercise(self, *, zot_failure=False, archive_failure=False, blob_failure=False, tool=True):
        token = synthetic_jwt()
        forgejo = synthetic_jwt(aud=probe.original.FORGEJO_AUDIENCE)
        body = json.dumps({'schemaVersion': 2, 'mediaType': probe.consumer.OCI_MEDIA_TYPE,
                           'config': {}, 'layers': []}).encode()
        digest = 'sha256:' + hashlib.sha256(body).hexdigest()
        evidence = {name + suffix: b'SYNTHETIC_SIGNED_BYTES' for name in
                    ('release-manifest', 'release-provenance') for suffix in ('.json', '.sigstore.json')}
        calls=[]; directories=[]
        def get(route, reference, credential, factory, *, product):
            self.assertEqual(product,'analytics');calls.append(route)
            if route=='zot':
                self.assertEqual(reference,digest);self.assertEqual(credential,token)
                if zot_failure:raise ValueError('PRIVATE '+token)
                return body, {'docker-content-digest':digest}
            self.assertEqual((route,reference,credential),('forgejo',probe.PINNED_VERSION,forgejo))
            return b'fixed-private-package', {}
        def run(argv, **kwargs):
            self.assertNotIn(token,repr(argv));self.assertNotIn(token,repr(kwargs['env']))
            self.assertNotIn(forgejo,repr(argv));self.assertNotIn(forgejo,repr(kwargs['env']))
            self.assertIn('--certificate-identity',argv);self.assertIn(probe.EXPECTED_CERTIFICATE_IDENTITY,argv)
            self.assertIn('--certificate-oidc-issuer',argv);self.assertIn(probe.EXPECTED_CERTIFICATE_ISSUER,argv)
            self.assertEqual(kwargs['stdout'],subprocess.DEVNULL);self.assertEqual(kwargs['stderr'],subprocess.DEVNULL)
            home=Path(kwargs['env']['HOME']);directories.append(home)
            config=home/'.docker/config.json'
            self.assertEqual(home.stat().st_mode&0o777,0o700)
            self.assertEqual(config.stat().st_mode&0o777,0o600)
            data=json.loads(config.read_bytes());encoded=data['auths'][probe.consumer.ZOT_HOST]['auth']
            self.assertEqual(base64.b64decode(encoded).decode(),'oidc:'+token)
            if argv[1]=='verify':self.assertEqual(argv[-1],probe.PINNED_IMAGE)
            return subprocess.CompletedProcess(argv,1 if blob_failure and argv[1]=='verify-blob' and 'release-manifest.json' in argv[-1] else 0)
        output=io.StringIO()
        with patch.object(probe.time,'time',return_value=NOW), \
             patch.object(probe,'PINNED_DIGEST',digest), \
             patch.object(probe.consumer,'_get',side_effect=get), \
             patch.object(probe.original,'_oidc_token',return_value=forgejo) as issue, \
             patch.object(probe,'_analytics_archive',side_effect=ValueError('PRIVATE '+forgejo) if archive_failure else None,return_value=(evidence,{})), \
             patch.object(probe,'_signed_fields',return_value=({},{})), \
             patch.object(probe.shutil,'which',return_value='/ci/cosign' if tool else None), \
             patch.object(probe.subprocess,'run',side_effect=run) as process,redirect_stdout(output):
            result=probe.run(ENVIRONMENT,token)
        issue.assert_called_once_with(ENVIRONMENT,audience=probe.original.FORGEJO_AUDIENCE)
        text=output.getvalue();self.assertNotIn(token,text);self.assertNotIn(forgejo,text);self.assertNotIn('PRIVATE',text)
        report=json.loads(text.splitlines()[0]);self.assertFalse(report['deployment_authorized']);self.assertFalse(report['host_state_changed'])
        for directory in directories:self.assertFalse(directory.exists())
        self.assertEqual(calls,['zot','forgejo'])
        return result,{r['name']:r['status'] for r in report['checks']},process.call_count

    def test_success_uses_exact_reads_real_cli_boundary_and_private_cleanup(self):
        result,checks,count=self.exercise();self.assertEqual(result,0)
        self.assertEqual(set(checks.values()),{'PASS'});self.assertEqual(count,3)

    def test_independent_transport_and_blob_failures_both_remain_visible(self):
        result,checks,count=self.exercise(zot_failure=True,blob_failure=True)
        self.assertEqual(result,2);self.assertEqual(count,3)
        self.assertEqual(checks['zot_authenticated_manifest'],'HOLD')
        self.assertEqual(checks['release_manifest_signature'],'HOLD')
        self.assertEqual(checks['forgejo_authenticated_package'],'PASS')
        self.assertEqual(checks['release_provenance_signature'],'PASS')
        self.assertEqual(checks['oci_signature'],'PASS')

    def test_archive_failure_blocks_blob_checks_but_continues_oci_verification(self):
        result,checks,count=self.exercise(archive_failure=True)
        self.assertEqual(result,2);self.assertEqual(count,1)
        self.assertEqual(checks['closed_analytics_archive'],'HOLD')
        self.assertEqual(checks['release_manifest_signature'],'BLOCKED')
        self.assertEqual(checks['oci_signature'],'PASS')

    def test_missing_cosign_preserves_transport_and_parser_diagnostics(self):
        result,checks,count=self.exercise(tool=False)
        self.assertEqual(result,2);self.assertEqual(count,0)
        self.assertEqual(checks['pinned_ci_cosign_available'],'HOLD')
        self.assertEqual(checks['release_fields_and_scanner_bindings'],'PASS')

    def test_wrong_workflow_cannot_acquire_private_evidence(self):
        with patch.object(probe.consumer,'_get') as get:
            with self.assertRaises(probe.original.ProbeUnavailableError):
                probe.run({**ENVIRONMENT,'GITHUB_REF':'refs/heads/unreviewed'},synthetic_jwt())
        get.assert_not_called()

    def test_arbitrary_oidc_audience_is_rejected_before_network(self):
        with patch.object(probe.original.request,'build_opener') as opener:
            with self.assertRaises(probe.original.ProbeUnavailableError):
                probe.original._oidc_token(ENVIRONMENT,audience='https://other.invalid')
            with self.assertRaises(probe.original.ProbeUnavailableError):
                probe.original._claims_preflight(synthetic_jwt(),ENVIRONMENT,NOW,audience='https://other.invalid')
        opener.assert_not_called()


if __name__=='__main__':
    unittest.main()
