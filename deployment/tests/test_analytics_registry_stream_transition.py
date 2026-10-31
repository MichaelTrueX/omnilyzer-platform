"""File: deployment/tests/test_analytics_registry_stream_transition.py

Purpose: Exercise exact registry deadline publication and stopped recovery.
Related: analytics_registry_stream_transition.py; original permission transaction.
Filesystem operations are real; service operations and server IDs are modeled.
"""
import copy
from contextlib import nullcontext,redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

def unique(rows):
    result={}
    for key,value in rows:
        if key in result:raise ValueError('duplicate')
        result[key]=value
    return result

def field(value,name,default=None):
    keys=[k for k in value if k.casefold()==name.casefold()]
    if len(keys)>1:raise ValueError('ambiguous')
    return value[keys[0]] if keys else default

helper=SimpleNamespace(unique=unique,field=field,service=lambda name:None,inspect=lambda:None)
spec=importlib.util.spec_from_file_location('registry_stream_transition',Path(__file__).resolve().parents[1]/'analytics_registry_stream_transition.py')
op=importlib.util.module_from_spec(spec);spec.loader.exec_module(op)



class FixtureBackupPath(type(Path())):
    """Project only this test's backup-directory owner to the server IDs."""
    def lstat(self):
        values=list(super().lstat());values[4]=values[5]=0
        return os.stat_result(values)


class StreamDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='registry-transaction-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.config=self.root/'config.json';self.backup=FixtureBackupPath(self.root/'backup');self.candidate=self.root/'candidate.json'
        model={'storage':{'rootDirectory':'/srv/omnilyzer-registry/zot','gc':False},
               'http':{'address':'127.0.0.1','port':'5000','readTimeout':'60s',
                       'auth':{'private_fixture':'MUST_REMAIN_PRIVATE'},
                       'accessControl':{'repositories':{'omnilyzer/analytics':{'policies':[{'actions':['read']}]}}}}}
        self.old=(json.dumps(model,indent=2)+'\n').encode();self.config.write_bytes(self.old);self.config.chmod(0o640)
        self.events=[]
        for key,value in [('CONFIG',self.config),('BACKUP',self.backup),('CANDIDATE',self.candidate),('OLD_SHA',op.sha(self.old))]:
            p=patch.object(op,key,value);p.start();self.addCleanup(p.stop)
        real_read=op.read
        fixture_uid,fixture_gid=os.getuid(),os.getgid()
        p=patch.object(op,'read',side_effect=lambda path,**kw:real_read(Path(str(path)),**{**kw,'owner':fixture_uid,'gid':fixture_gid}));p.start();self.addCleanup(p.stop)
        p=patch.object(op.os,'fchown',return_value=None);p.start();self.addCleanup(p.stop)
        for key,value in [('inspector',lambda:helper),('configuration_lock',nullcontext),
                          ('ready',lambda h:None),('verify',lambda p:self.events.append(('verify',p))),
                          ('command',lambda args,**kw:self.events.append(tuple(args)))]:
            p=patch.object(op,key,side_effect=value);p.start();self.addCleanup(p.stop)
        p=patch.object(helper,'service',return_value={'ActiveState':'active','MainPID':'123'});p.start();self.addCleanup(p.stop)
        p=patch.object(helper,'inspect',return_value={'checks':[{'name':'fixture','status':'PASS'}]});p.start();self.addCleanup(p.stop)
        for name in ('getuid','geteuid'):
            p=patch.object(op.os,name,return_value=0);p.start();self.addCleanup(p.stop)
        p=patch.object(op.socket,'gethostname',return_value='truexmainserver');p.start();self.addCleanup(p.stop)
        p=patch.object(op.sys,'argv',['operator']);p.start();self.addCleanup(p.stop)

    def run_apply(self,output=None):
        with redirect_stdout(output if output is not None else io.StringIO()):
            before=self.old;after=op.target(helper,before)
            with patch.object(op,'preflight',return_value=(before,after,{'nginx.service':{'ActiveState':'active','MainPID':'123'},'forgejo.service':{'ActiveState':'active','MainPID':'123'}})):
                op.main()
        return after

    def test_only_write_deadline_changes_and_no_secret_is_reported(self):
        after=json.loads(op.target(helper,self.old));before=json.loads(self.old)
        self.assertEqual(after['http'].pop('writeTimeout'),'900s')
        self.assertEqual(after,before)
        output=io.StringIO()
        self.run_apply(output)
        self.assertEqual(json.loads(output.getvalue())['status'],'REGISTRY_RESPONSE_WRITE_TIMEOUT_INSTALLED')
        self.assertNotIn('MUST_REMAIN_PRIVATE',output.getvalue())

    def test_existing_or_case_variant_write_deadline_is_not_adopted(self):
        for key in ('writeTimeout','WriteTimeout'):
            value=json.loads(self.old);value['http'][key]='1s';raw=json.dumps(value).encode()
            with self.subTest(key=key),patch.object(op,'OLD_SHA',op.sha(raw)):
                with self.assertRaisesRegex(RuntimeError,'WRITE_TIMEOUT_PREIMAGE'):op.target(helper,raw)

    def test_changed_preimage_never_becomes_authority(self):
        with self.assertRaisesRegex(RuntimeError,'REVIEWED_CONFIGURATION_CHANGED'):op.target(helper,self.old+b' ')

    def test_success_retains_private_backup_and_changes_only_zot_service(self):
        after=self.run_apply();self.assertEqual(self.config.read_bytes(),after)
        self.assertEqual((self.backup/'before.json').read_bytes(),self.old)
        self.assertEqual(self.backup.stat().st_mode&0o777,0o700)
        self.assertEqual((self.backup/'before.json').stat().st_mode&0o777,0o600)
        self.assertEqual([e for e in self.events if e[0]=='/usr/bin/systemctl'],[('/usr/bin/systemctl','restart','zot.service')])

    def test_failed_restart_automatically_restores_old_config(self):
        count=0
        def command(args,**kwargs):
            nonlocal count
            count+=1
            if count==1:raise RuntimeError('INJECTED_RESTART_FAILURE')
        with patch.object(op,'command',side_effect=command):
            with self.assertRaisesRegex(RuntimeError,'INJECTED_RESTART_FAILURE'):self.run_apply()
        self.assertEqual(self.config.read_bytes(),self.old);self.assertEqual(count,2)

    def test_failed_candidate_validation_never_publishes_or_restarts(self):
        with patch.object(op,'verify',side_effect=RuntimeError('INJECTED_VALIDATION_FAILURE')):
            with self.assertRaisesRegex(RuntimeError,'INJECTED_VALIDATION_FAILURE'):self.run_apply()
        self.assertEqual(self.config.read_bytes(),self.old)
        self.assertFalse(any(e[0]=='/usr/bin/systemctl' for e in self.events))

    def test_unknown_config_during_recovery_is_preserved(self):
        self.run_apply();self.config.write_bytes(b'UNKNOWN');self.config.chmod(0o640)
        with self.assertRaisesRegex(RuntimeError,'UNKNOWN_CONFIGURATION_PRESERVED'):op.recover(helper)
        self.assertEqual(self.config.read_bytes(),b'UNKNOWN')

    def test_independent_preflight_failures_are_all_reported_before_writes(self):
        self.config.write_bytes(b'CHANGED');self.config.chmod(0o640);self.backup.mkdir()
        output=io.StringIO()
        with redirect_stdout(output):
            with self.assertRaisesRegex(RuntimeError,'COMPLETE_PREFLIGHT_FAILED'):op.preflight(helper)
        report=json.loads(output.getvalue());failures={c['name'] for c in report['checks'] if c['status']=='FAIL'}
        self.assertIn('exact_response_write_timeout_only_delta',failures);self.assertIn('unused_path:backup',failures)
        self.assertFalse(self.candidate.exists());self.assertFalse(self.events)

    def test_explicit_unknown_recovery_attempts_stop_only_registry(self):
        self.run_apply();self.config.write_bytes(b'UNKNOWN');self.config.chmod(0o640)
        self.events.clear()
        with patch.object(op.sys,'argv',['operator','--recover']), \
             patch.object(helper,'service',return_value={'ActiveState':'inactive','MainPID':'0'}),redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError,'UNKNOWN_CONFIGURATION_PRESERVED'):op.main()
        self.assertEqual(self.config.read_bytes(),b'UNKNOWN')
        self.assertEqual(self.events,[('/usr/bin/systemctl','stop','zot.service')])

    def test_incomplete_preparation_qualifies_unchanged_old_state_without_rollback_claim(self):
        self.backup.mkdir(mode=0o700);(self.backup/'before.json').write_bytes(b'PARTIAL')
        output=io.StringIO()
        with redirect_stdout(output):op.recover(helper)
        self.assertEqual(self.config.read_bytes(),self.old);self.assertFalse(self.events)
        self.assertEqual(json.loads(output.getvalue())['status'],'PREPARATION_FAILED_CONFIGURATION_UNCHANGED')

    def test_known_complete_restore_file_can_be_reused_after_interruption(self):
        self.run_apply();op.write(self.backup/'restore.json',self.old,gid=988,mode=0o640)
        with redirect_stdout(io.StringIO()):op.recover(helper)
        self.assertEqual(self.config.read_bytes(),self.old)

    def test_both_backup_names_present_with_partial_after_are_pre_cutover(self):
        self.backup.mkdir(mode=0o700)
        (self.backup/'before.json').write_bytes(self.old)
        (self.backup/'after.json').write_bytes(b'PARTIAL')
        (self.backup/'ready.tmp').write_bytes(b'PARTIAL_MARKER')
        output=io.StringIO()
        with redirect_stdout(output):op.recover(helper)
        self.assertFalse(self.events);self.assertEqual(self.config.read_bytes(),self.old)
        self.assertEqual(json.loads(output.getvalue())['status'],'PREPARATION_FAILED_CONFIGURATION_UNCHANGED')

    def test_old_config_with_complete_ready_marker_still_restarts_for_coherent_recovery(self):
        self.run_apply();self.config.write_bytes(self.old);self.config.chmod(0o640);self.events.clear()
        with redirect_stdout(io.StringIO()):op.recover(helper)
        self.assertIn(('/usr/bin/systemctl','restart','zot.service'),self.events)


if __name__=='__main__':unittest.main()
