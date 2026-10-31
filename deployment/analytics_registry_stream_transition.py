#!/usr/bin/env python3
"""File: deployment/analytics_registry_stream_transition.py

Purpose: Apply the exact owner-reviewed Zot response-write deadline correction.
Related: analytics_registry_stream_readiness.py, native Zot stream regression,
         original registry read-permission transition and Task014 issue27.

Only http.writeTimeout becomes900s. Existing OIDC/access policy, storage,
read timeout, private data and unrelated services are preserved. Retain the
existing transaction/explicit recovery mechanics; import has no host action.
"""
from __future__ import annotations
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import time
import types
from contextlib import contextmanager

CONFIG=Path('/etc/zot/config.json')
HELPER=Path('/home/trusthansen/omnilyzer-task014-registry-readiness.py')
HELPER_SHA='b0866380e99a9903b97d8999e1879c8835c07499e2083b9f58838b4173071169'
OLD_SHA='880dca7bb8aede9a833e31e938abc7b6f2ee1dd96911be927de6ce5502318d1a'
BACKUP=Path('/etc/zot/.task014-stream-20261031')
CANDIDATE=Path('/etc/zot/.task014-stream-next.json')
WRITE_TIMEOUT='900s'
BINARY_SHA='a32e42d042d1f17b5b1317e55cc1a415a744c873dcd05c25c56b665478258bcb'


def need(ok,code):
    if not ok:raise RuntimeError(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def read(path,*,gid,mode,maximum=1048576,owner=0):
    before=path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and
         (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode))==(owner,gid,mode)
         and 0<before.st_size<=maximum,'FILE_METADATA')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        raw=bytearray()
        while len(raw)<=maximum:
            block=os.read(fd,min(65536,maximum+1-len(raw)))
            if not block:break
            raw.extend(block)
        fp=lambda m:(m.st_dev,m.st_ino,m.st_mode,m.st_uid,m.st_gid,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
        need(fp(before)==fp(os.fstat(fd))==fp(path.lstat()) and len(raw)==before.st_size,'FILE_CHANGED')
        return bytes(raw)
    finally:os.close(fd)


def inspector():
    raw=read(HELPER,gid=1000,mode=0o600,maximum=32768,owner=1000)
    need(sha(raw)==HELPER_SHA,'INSPECTOR_HASH')
    module=types.ModuleType('reviewed_registry_inspector')
    exec(compile(raw,str(HELPER),'exec'),module.__dict__)
    return module


def target(helper,raw):
    """Bind the exact live preimage and prove a one-field semantic delta."""
    need(sha(raw)==OLD_SHA,'REVIEWED_CONFIGURATION_CHANGED')
    before=json.loads(raw,object_pairs_hook=helper.unique)
    after=copy.deepcopy(before)
    http=helper.field(after,'http')
    need(type(http) is dict and not any(key.casefold()=='writetimeout' for key in http),'WRITE_TIMEOUT_PREIMAGE')
    http['writeTimeout']=WRITE_TIMEOUT
    restored=copy.deepcopy(after)
    need(helper.field(restored,'http').pop('writeTimeout')==WRITE_TIMEOUT and restored==before,'ONLY_RESPONSE_WRITE_TIMEOUT_MAY_CHANGE')
    output=(json.dumps(after,indent=2,ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')
    need(json.loads(output,object_pairs_hook=helper.unique)==after,'TARGET_JSON_ROUNDTRIP')
    return output


def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)


def write(path,raw,*,gid=0,mode=0o600):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        view=memoryview(raw)
        while view:
            amount=os.write(fd,view);need(amount>0,'SHORT_WRITE');view=view[amount:]
        os.fchown(fd,0,gid);os.fchmod(fd,mode);os.fsync(fd)
    finally:os.close(fd)
    need(read(path,gid=gid,mode=mode)==raw,'WRITTEN_BYTES');sync(path.parent)


def command(args,timeout=30):
    result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                          timeout=timeout,check=False,cwd='/srv/omnilyzer-registry/zot',
                          env={'PATH':'/usr/bin:/bin','LANG':'C','HOME':'/srv/omnilyzer-registry/zot'})
    need(result.returncode==0,'NATIVE_COMMAND_FAILED')


def verify(path):command(('/usr/local/bin/zot','verify',str(path)),timeout=30)


def ready(helper):
    """Stable active service and private HTTP endpoint; no authenticated claim."""
    for _ in range(15):
        try:
            value=helper.service('zot.service')
            need(value['ActiveState']=='active' and int(value['MainPID'])>0,'ZOT_NOT_ACTIVE')
            connection=http.client.HTTPConnection('127.0.0.1',5000,timeout=2)
            try:
                connection.request('GET','/v2/');response=connection.getresponse()
                need(response.status==401,'REGISTRY_NOT_READY');response.close()
            finally:connection.close()
            time.sleep(0.5)
            need(helper.service('zot.service')==value,'ZOT_NOT_STABLE')
            return
        except Exception:time.sleep(0.5)
    raise RuntimeError('REGISTRY_STABLE_START_FAILED')


def report(status,**extra):
    print(json.dumps({'status':status,'operation':'task014_registry_stream_deadline','write_timeout':WRITE_TIMEOUT,
          'application_acceptance':'NOT_YET_VERIFIED','registry_data_or_secret_changes':False,**extra},sort_keys=True),flush=True)


def preflight(helper):
    """Complete independent read-only matrix before creating any backup/file."""
    matrix=helper.inspect();checks=matrix['checks']
    def check(name,operation):
        try:
            value=operation();checks.append({'name':name,'status':'PASS'});return value
        except Exception as error:
            checks.append({'name':name,'status':'FAIL','error':error_code(error)});return None
    loaded=check('reviewed_configuration_bytes',lambda:read(CONFIG,gid=988,mode=0o640))
    after=check('exact_response_write_timeout_only_delta',lambda:target(helper,loaded)) if loaded is not None else None
    if loaded is None:checks.append({'name':'exact_response_write_timeout_only_delta','status':'BLOCKED'})
    for path in (BACKUP,CANDIDATE):
        check('unused_path:'+path.name,lambda p=path:need(not p.exists() and not p.is_symlink(),'PRIOR_OPERATION_STATE_PRESERVED'))
    def binary():
        p=Path('/usr/local/bin/zot');m=p.lstat()
        need(stat.S_ISREG(m.st_mode) and m.st_uid==0 and m.st_nlink==1 and not m.st_mode&0o022
             and m.st_mode&0o111,'NATIVE_VERIFIER_METADATA')
        need(sha(read(p,gid=0,mode=0o755,maximum=225001774))==BINARY_SHA,'NATIVE_VERIFIER_HASH')
    check('existing_native_verifier',binary)
    others={}
    for unit in ('zot.service','nginx.service','forgejo.service'):
        def active(name=unit):
            value=helper.service(name);need(value['ActiveState']=='active' and int(value['MainPID'])>0,'EXPECTED_SERVICE_NOT_ACTIVE');return value
        value=check('active:'+unit,active)
        if unit!='zot.service' and value is not None:others[unit]=value
    print(json.dumps(matrix,sort_keys=True),flush=True)
    need(all(row['status']=='PASS' for row in checks),'COMPLETE_PREFLIGHT_FAILED')
    return loaded,after,others


def error_code(error):
    import re
    value=str(error) if type(error) is RuntimeError else 'UNEXPECTED_'+type(error).__name__.upper()
    return value if re.fullmatch(r'[A-Z][A-Z0-9_]{0,95}',value) else 'UPDATE_FAILED'


@contextmanager
def configuration_lock():
    import fcntl
    directory=os.open(CONFIG.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        meta=os.fstat(directory);need((meta.st_uid,meta.st_gid,stat.S_IMODE(meta.st_mode))==(0,988,0o750),'REGISTRY_DIRECTORY_METADATA')
        fcntl.flock(directory,fcntl.LOCK_EX|fcntl.LOCK_NB)
        need((meta.st_dev,meta.st_ino)==(CONFIG.parent.lstat().st_dev,CONFIG.parent.lstat().st_ino),'CONFIG_DIRECTORY_CHANGED')
        yield
    finally:os.close(directory)


def recover(helper):
    meta=BACKUP.lstat();need(stat.S_ISDIR(meta.st_mode) and (meta.st_uid,meta.st_gid,stat.S_IMODE(meta.st_mode))==(0,0,0o700),'BACKUP_METADATA')
    # The durable marker is published atomically only after BOTH backups.
    # Its absence plus the pinned old config proves no cutover was started.
    if not (BACKUP/'ready.json').exists() and not (BACKUP/'ready.json').is_symlink():
        current=read(CONFIG,gid=988,mode=0o640)
        need(sha(current)==OLD_SHA,'INCOMPLETE_BACKUP_AND_CHANGED_CONFIGURATION')
        target(helper,current);ready(helper)
        report('PREPARATION_FAILED_CONFIGURATION_UNCHANGED',configuration_sha256=OLD_SHA)
        return
    old=read(BACKUP/'before.json',gid=0,mode=0o600)
    need(sha(old)==OLD_SHA,'ROLLBACK_PREIMAGE_HASH')
    new=target(helper,old)
    need(read(BACKUP/'after.json',gid=0,mode=0o600)==new,'ROLLBACK_TARGET_HASH')
    need(read(BACKUP/'ready.json',gid=0,mode=0o600)==ready_marker(new),'ROLLBACK_MARKER_HASH')
    current=read(CONFIG,gid=988,mode=0o640)
    need(current in (old,new),'UNKNOWN_CONFIGURATION_PRESERVED')
    if current==new:
        rollback=BACKUP/'restore.json'
        if rollback.exists() or rollback.is_symlink():
            need(read(rollback,gid=988,mode=0o640)==old,'UNKNOWN_RESTORE_FILE_PRESERVED')
        else:write(rollback,old,gid=988,mode=0o640)
        verify(rollback)
        need(read(CONFIG,gid=988,mode=0o640)==new,'ROLLBACK_CONCURRENT_CHANGE')
        os.replace(rollback,CONFIG);sync(CONFIG.parent)
    command(('/usr/bin/systemctl','restart','zot.service'),timeout=90);ready(helper)
    report('PREVIOUS_REGISTRY_CONFIGURATION_RECOVERED',configuration_sha256=OLD_SHA)


def stop_after_recovery_failure(helper):
    try:
        command(('/usr/bin/systemctl','stop','zot.service'))
        need(helper.service('zot.service')['ActiveState']=='inactive','STOP_NOT_CONFIRMED')
        report('REGISTRY_STOPPED_MANUAL_RECOVERY_REQUIRED')
    except BaseException:report('REGISTRY_MANUAL_STOP_AND_RECOVERY_REQUIRED')


def ready_marker(after):
    return (json.dumps({'operation':'task014-registry-stream','before_sha256':OLD_SHA,
                        'after_sha256':sha(after)},sort_keys=True)+'\n').encode('ascii')


def main():
    os.umask(0o077)
    need(sys.argv[1:] in ([],['--recover']) and os.getuid()==os.geteuid()==0
         and socket.gethostname().split('.')[0]=='truexmainserver','OWNER_LOCAL_REGISTRY_ROOT_REQUIRED')
    helper=inspector()
    with configuration_lock():
        if sys.argv[1:]:
            try:recover(helper)
            except BaseException:stop_after_recovery_failure(helper);raise
            return
        before,after,others=preflight(helper)
        BACKUP.mkdir(mode=0o700);sync(CONFIG.parent)
        write(BACKUP/'before.json',before);write(BACKUP/'after.json',after)
        write(BACKUP/'ready.tmp',ready_marker(after))
        os.rename(BACKUP/'ready.tmp',BACKUP/'ready.json');sync(BACKUP)
        changed=False
        try:
            write(CANDIDATE,after,gid=988,mode=0o640);verify(CANDIDATE)
            need(read(CONFIG,gid=988,mode=0o640)==before,'CONFIGURATION_CHANGED_BEFORE_PUBLISH')
            os.replace(CANDIDATE,CONFIG);changed=True;sync(CONFIG.parent)
            command(('/usr/bin/systemctl','restart','zot.service'),timeout=90);ready(helper)
            need(read(CONFIG,gid=988,mode=0o640)==after,'INSTALLED_TARGET_CHANGED')
            need(all(helper.service(unit)==value for unit,value in others.items()),'OTHER_SERVICE_CHANGED')
            report('REGISTRY_RESPONSE_WRITE_TIMEOUT_INSTALLED',previous_sha256=OLD_SHA,configuration_sha256=sha(after))
        except BaseException:
            # Inspect actual bytes as well: interruption may follow atomic rename.
            try:
                current=read(CONFIG,gid=988,mode=0o640)
                if changed or current!=before:recover(helper)
                else:report('PREPARATION_FAILED_CONFIGURATION_UNCHANGED',configuration_sha256=OLD_SHA)
            except BaseException:
                stop_after_recovery_failure(helper)
            raise


if __name__=='__main__':
    try:main()
    except Exception as error:print('REGISTRY_STREAM_UPDATE_NOT_COMPLETED',error_code(error),flush=True);raise SystemExit(1)
