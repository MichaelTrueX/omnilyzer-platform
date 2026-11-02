"""Bounded new32 parser tests. Synthetic archives grant no install authority.

The owner entrypoint separately requires its exact input-manifest/asset hashes.
No host, service, registry, secret, database or replay operation occurs here.
"""
import copy
import io
import json
from pathlib import Path
import tarfile
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from deployment import analytics_task014_resume as owner
from deployment.analytics_executor_service_config import ANALYTICS_INSTALLED_FILES, _INSTALLED_RUNTIME_FILES
from deployment.analytics_source_handoff import _ADDITIVE_UNITS, _SHARED_COMPATIBILITY_FILES, _SHARED_PREIMAGE_SHA256, _SHARED_PREIMAGE_COMMITS
from deployment.application_source_set import DevApplicationSourceSet
from deployment.analytics_execution import AnalyticsRequestError, parse_analytics_request
from deployment.tests.test_analytics_execution import EXPECTED


def unique(pairs):
    result = {}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate')
        result[key] = value
    return result


class ExactTransportGeneration(unittest.TestCase):
    def setUp(self):
        self.helper = SimpleNamespace(unique=unique)
        patches = [p for p in _SHARED_COMPATIBILITY_FILES if p != owner.TRANSPORT_SOURCE]
        paths = sorted((*ANALYTICS_INSTALLED_FILES,*_INSTALLED_RUNTIME_FILES,*_ADDITIVE_UNITS,*patches))
        self.data = {p: ('synthetic-payload:'+p).encode() for p in paths}
        inherited = {p.repository_path:'a'*64 for p in DevApplicationSourceSet().files if p.repository_path not in patches}
        inherited[owner.TRANSPORT_SOURCE] = owner.TRANSPORT_PREIMAGE
        self.old = dict(schema_version=1,purpose='analytics-task014-additive-source-review-only',source_commit=owner.IDENTITY_TARGET,source_repository='MichaelTrueX/omnilyzer-platform',source_file_count=31,source_entries=[dict(path=p,mode='0644',sha256=owner.digest(self.data[p])) for p in paths],shared_base_source_commit='b9e22e745ecbaf96dc15998e91d1a74f70e5ad77',shared_patch_paths=patches,shared_preimage_sha256={p:_SHARED_PREIMAGE_SHA256[p] for p in patches},shared_preimage_commits={p:_SHARED_PREIMAGE_COMMITS[p] for p in patches},inherited_canary_sha256=inherited,isolation_target='/opt/omnilyzer/deployment/analytics-app',reviewed_compose_sha256='a'*64,reviewed_product_profile_sha256='b'*64,reviewed_runtime_profile_sha256='c'*64,reviewed_source_claim_sha256='d'*64,signed_release_authorized=False,deployment_authorized=False)
        self.data[owner.TRANSPORT_SOURCE] = (Path(__file__).resolve().parents[1]/'unix_transport.py').read_bytes()
        self.model = copy.deepcopy(self.old)
        self.model.update(source_commit=owner.TRANSPORT_TARGET,source_file_count=32,source_entries=[dict(path=p,mode='0644',sha256=owner.digest(self.data[p])) for p in sorted(self.data)],shared_patch_paths=list(_SHARED_COMPATIBILITY_FILES),shared_preimage_sha256=dict(_SHARED_PREIMAGE_SHA256),shared_preimage_commits=dict(_SHARED_PREIMAGE_COMMITS),inherited_canary_sha256={p:s for p,s in inherited.items() if p != owner.TRANSPORT_SOURCE})

    def archive(self, model=None, *, omit=None, replace=None):
        data = {'.omnilyzer-analytics-source-review.json':owner.canonical(self.model if model is None else model),**self.data}
        if omit is not None:data.pop(omit)
        if replace is not None:data.update(replace)
        output = io.BytesIO()
        with tarfile.open(fileobj=output,mode='w',format=tarfile.USTAR_FORMAT) as tar:
            for path in ('.omnilyzer-analytics-source-review.json',*sorted(p for p in data if p != '.omnilyzer-analytics-source-review.json')):
                raw=data[path]
                info=tarfile.TarInfo(path);info.size=len(raw);info.mode=0o644;info.uid=info.gid=info.mtime=0;info.uname=info.gname=''
                tar.addfile(info,io.BytesIO(raw))
        return output.getvalue()

    def test_exact32_payloads38_inherited_preserve_same70_paths(self):
        model,hashes=owner.transport_source_model(self.helper,self.archive(),self.old)
        self.assertEqual((len(model['source_entries']),len(model['inherited_canary_sha256']),len(hashes)),(32,38,70))
        self.assertEqual(set(hashes),set(self.old['inherited_canary_sha256'])|{r['path'] for r in self.old['source_entries']})
        self.assertEqual(hashes[owner.TRANSPORT_SOURCE],owner.TRANSPORT_SOURCE_SHA)

    def test_counts_authorization_types_and_existing_preimages_fail_closed(self):
        cases=[{**self.model,'source_file_count':31},{**self.model,'deployment_authorized':0},{**self.model,'signed_release_authorized':0},{**self.model,'schema_version':True},{**self.model,'shared_preimage_sha256':{**self.model['shared_preimage_sha256'],'deployment/promotion.py':'0'*64}}]
        for value in cases:
            with self.subTest(value=value.keys()),self.assertRaises(owner.ServiceFailure):
                owner.transport_source_model(self.helper,self.archive(value),self.old)

    def test_missing_modified_or_trailing_archive_data_is_not_admitted(self):
        cases=[self.archive(omit=owner.TRANSPORT_SOURCE),self.archive(replace={owner.TRANSPORT_SOURCE:b'changed'}),self.archive()+b'\0'*512]
        for raw in cases:
            with self.subTest(size=len(raw)),self.assertRaises(owner.ServiceFailure):
                owner.transport_source_model(self.helper,raw,self.old)

    def test_actual_old31_and_new32_inputs_join_through_inherited_unix_preimage(self):
        """Build both exact Git generations with their own production builders.

        Only protected-file ownership is projected; original bytes, archive
        validators, configs, approvals and the new transition delta run for real.
        """
        repository = Path(__file__).resolve().parents[2]
        commits = (owner.IDENTITY_TARGET,owner.TRANSPORT_TARGET)
        program = r'''import sys,json,hashlib,tarfile,io
from pathlib import Path
root,commit,output=sys.argv[1:];sys.path.insert(0,root)
from deployment.analytics_dev_activation_inputs import build_unsigned_analytics_activation_inputs,build_unsigned_analytics_service_inputs
from deployment.analytics_source_archive import verify_analytics_source_archive
values=build_unsigned_analytics_activation_inputs(repository_root=root,reviewed_commit=commit);values.update(build_unsigned_analytics_service_inputs(repository_root=root,reviewed_commit=commit))
paths=('/etc/omnilyzer/deployment/broker/analytics.json','/etc/omnilyzer/deployment/dev/analytics-executor.json','/etc/omnilyzer/deployment/dev/analytics-source-install.json','/etc/systemd/system/omnilyzer-deployment-analytics-executor.service','/etc/systemd/system/omnilyzer-deployment-analytics-executor.service.d/rootless-runtime.conf','/etc/systemd/system/omnilyzer-deployment-analytics-executor.socket','/etc/systemd/system/omnilyzer-deployment-broker.service.d/analytics-enabled.conf','/opt/omnilyzer/deployment/.analytics-source-review.tar')
for index,path in enumerate(paths):Path(output,str(index)).write_bytes(values[path])
raw=values[paths[7]]
with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as tar:manifest=tar.extractfile('.omnilyzer-analytics-source-review.json').read()
verify_analytics_source_archive(raw,expected_manifest_sha256=hashlib.sha256(manifest).hexdigest(),reviewed_commit=commit)
Path(output,'model.json').write_bytes(manifest)
'''
        with tempfile.TemporaryDirectory(prefix='analytics-fixed-inputs-') as folder:
            folder=Path(folder);trees=[];outputs=[]
            try:
                for index,commit in enumerate(commits):
                    tree=folder/('source-'+str(index));output=folder/('inputs-'+str(index));output.mkdir()
                    subprocess.run(['git','-c','core.hooksPath=/dev/null','worktree','add','--detach',str(tree),commit],cwd=repository,check=True,capture_output=True)
                    trees.append(tree);outputs.append(output)
                    subprocess.run([sys.executable,'-I','-B','-c',program,str(tree),commit,str(output)],cwd=tree,check=True,capture_output=True,text=True,timeout=60)
                old={i:(outputs[0]/str(i)).read_bytes() for i in range(8)}
                new={i:(outputs[1]/str(i)).read_bytes() for i in range(8)}
                old_model=json.loads((outputs[0]/'model.json').read_text())
                self.assertEqual(old_model['source_file_count'],31)
                self.assertNotIn(owner.TRANSPORT_SOURCE,{r['path'] for r in old_model['source_entries']})
                old_hashes={**old_model['inherited_canary_sha256'],**{r['path']:r['sha256'] for r in old_model['source_entries']}}
                def old31(raw,commit):
                    self.assertEqual((raw,commit),(old[7],owner.IDENTITY_TARGET));return old_model,old_hashes
                def protected(path,maximum,**metadata):
                    self.assertEqual(path,trees[0]/owner.TRANSPORT_SOURCE)
                    self.assertEqual(metadata,dict(owner=0,group=0,mode=0o644))
                    raw=path.read_bytes();self.assertLessEqual(len(raw),maximum);return raw
                helper=SimpleNamespace(source_model=old31,bounded_file=protected,CANARY_ROOT=trees[0],unique=unique)
                before,after,old_source,new_source=owner.identity_delta(helper,old,new,transport=True)
                self.assertEqual([p for p in before if before[p]!=after[p]],[owner.TRANSPORT_SOURCE])
                self.assertEqual((owner.digest(old_source),owner.digest(new_source)),(owner.TRANSPORT_PREIMAGE,owner.TRANSPORT_SOURCE_SHA))
            finally:
                for tree in reversed(trees):
                    subprocess.run(['git','-c','core.hooksPath=/dev/null','worktree','remove',str(tree)],cwd=repository,check=True,capture_output=True)

    def test_owner_sender_probe_body_is_invalid_before_credential_use_or_execution(self):
        compile(owner.TRANSPORT_REJECTION_CLIENT,'invalid-owner-sender','exec')
        with self.assertRaises(AnalyticsRequestError):parse_analytics_request(b'{}',**EXPECTED)
        self.assertNotIn('execute_private',owner.TRANSPORT_REJECTION_CLIENT)
        self.assertIn("body=b'{}'",owner.TRANSPORT_REJECTION_CLIENT)


if __name__=='__main__':unittest.main()
