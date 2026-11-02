"""File: deployment/tests/test_analytics_stream_generation.py

Purpose: Join actual frozen31/32/32 builders through the exact stream cutover.
Related: analytics_task014_resume.py; test_analytics_transport_generation.py.
Only disposable Git worktrees and source artifacts; no root or service action.
"""
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deployment import analytics_task014_resume as owner
from deployment.tests.test_analytics_transport_generation import unique


class FrozenStreamGeneration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repository=Path(__file__).resolve().parents[2]
        cls.temporary=tempfile.TemporaryDirectory(prefix='analytics-stream-inputs-')
        cls.trees=[]
        program=r'''import sys,json,hashlib,io,tarfile
from pathlib import Path
root,commit,output=sys.argv[1:];sys.path.insert(0,root)
from deployment.analytics_dev_activation_inputs import build_unsigned_analytics_activation_inputs,build_unsigned_analytics_service_inputs
from deployment.analytics_source_archive import verify_analytics_source_archive
values=build_unsigned_analytics_activation_inputs(repository_root=root,reviewed_commit=commit);values.update(build_unsigned_analytics_service_inputs(repository_root=root,reviewed_commit=commit))
paths=('/etc/omnilyzer/deployment/broker/analytics.json','/etc/omnilyzer/deployment/dev/analytics-executor.json','/etc/omnilyzer/deployment/dev/analytics-source-install.json','/etc/systemd/system/omnilyzer-deployment-analytics-executor.service','/etc/systemd/system/omnilyzer-deployment-analytics-executor.service.d/rootless-runtime.conf','/etc/systemd/system/omnilyzer-deployment-analytics-executor.socket','/etc/systemd/system/omnilyzer-deployment-broker.service.d/analytics-enabled.conf','/opt/omnilyzer/deployment/.analytics-source-review.tar')
for index,path in enumerate(paths):Path(output,str(index)).write_bytes(values[path])
with tarfile.open(fileobj=io.BytesIO(values[paths[7]]),mode='r:') as tar:manifest=tar.extractfile('.omnilyzer-analytics-source-review.json').read()
verify_analytics_source_archive(values[paths[7]],expected_manifest_sha256=hashlib.sha256(manifest).hexdigest(),reviewed_commit=commit)
Path(output,'model.json').write_bytes(manifest)
'''
        cls.inputs=[];cls.models=[]
        try:
            for index,commit in enumerate((owner.IDENTITY_TARGET,owner.TRANSPORT_TARGET,owner.STREAM_TARGET)):
                tree=Path(cls.temporary.name)/('source-'+str(index));output=Path(cls.temporary.name)/('inputs-'+str(index));output.mkdir()
                subprocess.run(['git','-c','core.hooksPath=/dev/null','worktree','add','--detach',str(tree),commit],cwd=cls.repository,check=True,capture_output=True)
                cls.trees.append(tree)
                subprocess.run([sys.executable,'-I','-B','-c',program,str(tree),commit,str(output)],cwd=tree,check=True,capture_output=True,text=True,timeout=60)
                cls.inputs.append({i:(output/str(i)).read_bytes() for i in range(8)})
                cls.models.append(json.loads((output/'model.json').read_text()))
        except BaseException:
            cls.tearDownClass();raise

    @classmethod
    def tearDownClass(cls):
        for tree in reversed(cls.trees):
            subprocess.run(['git','-c','core.hooksPath=/dev/null','worktree','remove',str(tree)],cwd=cls.repository,check=True,capture_output=True)
        cls.temporary.cleanup()

    def delta(self,new):
        with patch.object(owner,'historical_model31',return_value=self.models[0]):
            return owner.stream_delta(SimpleNamespace(unique=unique),self.inputs[1],new)

    def rewrite(self,raw,*,changed_path=None,commit=None):
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as source:
            data={m.name:source.extractfile(m).read() for m in source.getmembers()}
        name='.omnilyzer-analytics-source-review.json';model=json.loads(data[name])
        if commit is not None:model['source_commit']=commit
        if changed_path is not None:
            data[changed_path]+=b'\n# unexpected extra source delta\n'
            for row in model['source_entries']:
                if row['path']==changed_path:row['sha256']=owner.digest(data[changed_path])
        data[name]=owner.canonical(model);output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w',format=tarfile.USTAR_FORMAT) as archive:
            for path in (name,*sorted(p for p in data if p!=name)):
                info=tarfile.TarInfo(path);info.size=len(data[path]);info.mode=0o644;info.uid=info.gid=info.mtime=0;info.uname=info.gname=''
                archive.addfile(info,io.BytesIO(data[path]))
        return output.getvalue()

    def test_exact_three_modules_same70_and_four_unchanged_service_assets(self):
        old,new,before,after=self.delta(self.inputs[2])
        self.assertEqual([m['source_file_count'] for m in self.models],[31,32,32])
        self.assertEqual((len(old),len(new)),(70,70))
        self.assertEqual(sorted(p for p in old if old[p]!=new[p]),list(owner.STREAM_SOURCES))
        self.assertEqual({p:owner.digest(before[p]) for p in before},owner.STREAM_PREIMAGES)
        self.assertEqual({p:owner.digest(after[p]) for p in after},owner.STREAM_HASHES)
        self.assertTrue(all(self.inputs[1][i]==self.inputs[2][i] for i in (3,4,5,6)))

    def test_additional_source_delta_never_becomes_authority(self):
        new=copy.deepcopy(self.inputs[2]);new[7]=self.rewrite(new[7],changed_path='deployment/analytics_executor.py')
        with self.assertRaisesRegex(owner.ServiceFailure,'stream_exact_source_delta'):self.delta(new)

    def test_changed_service_asset_is_rejected(self):
        new=copy.deepcopy(self.inputs[2]);new[3]+=b'\n'
        with self.assertRaisesRegex(owner.ServiceFailure,'stream_unit_delta'):self.delta(new)

    def test_wrong_source_configuration_is_rejected(self):
        new=copy.deepcopy(self.inputs[2]);config=json.loads(new[0]);config['source_sha256'][owner.STREAM_SOURCES[0]]='0'*64
        new[0]=new[1]=owner.canonical(config)
        with self.assertRaisesRegex(owner.ServiceFailure,'stream_configuration_delta'):self.delta(new)

    def test_unreviewed_candidate_commit_is_rejected(self):
        new=copy.deepcopy(self.inputs[2]);new[7]=self.rewrite(new[7],commit='c'*40)
        with self.assertRaisesRegex(owner.ServiceFailure,'transport_source_identity'):self.delta(new)


if __name__=='__main__':unittest.main()
