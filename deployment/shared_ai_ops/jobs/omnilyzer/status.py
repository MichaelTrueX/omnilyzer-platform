#!/usr/bin/python3
"""Omnilyzer private host readiness metadata, no mutations or secrets."""
import os
import sys

if __name__ == "__main__":
    if len(sys.argv) != 1 or os.geteuid() != 0 or os.uname().nodename != "omnilyzerdev":
        print("OMNI_AGENT_STATUS_HOLD_WRONG_HOST_OR_USER",file=sys.stderr)
        sys.exit(70)
    print("OMNI_AGENT_STATUS_DISPATCH_READY_NO_RELEASE_ACTION")
