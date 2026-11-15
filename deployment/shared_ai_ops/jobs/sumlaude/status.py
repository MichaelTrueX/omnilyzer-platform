#!/usr/bin/python3
"""Privacy-safe source and receipt metadata only, no database access."""
import os
from pathlib import Path
import stat
import sys

def main():
    if os.geteuid() or len(sys.argv) != 1 or os.uname().nodename != "truexmainserver":
        raise SystemExit("SUM_AGENT_STATUS_HOLD_CONTEXT")
    base=Path("/var/lib/sumlaude-s03-current35-108-110-once")
    if not base.is_dir() or base.is_symlink():
        print("SUM_AGENT_STATUS_NO_ROOT_RECEIPT_STAGE")
        return
    receipt=base/"receipts"
    st=receipt.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise SystemExit("SUM_AGENT_STATUS_HOLD_RECEIPT_CUSTODY")
    verified=receipt/"schema-verified.txt"
    if verified.is_file() and not verified.is_symlink():
        text=verified.read_text(encoding="utf-8")
        if "STATUS=POSTCOMMIT_SCHEMA_ONLY_PASS" in text.splitlines():
            print("SUM_AGENT_STATUS_108_109_110_POSTCOMMIT_RECEIPT_PRESENT_PASS")
            return
    raise SystemExit("SUM_AGENT_STATUS_HOLD_POSTCOMMIT_NOT_PROVED")

if __name__ == "__main__":
    main()
