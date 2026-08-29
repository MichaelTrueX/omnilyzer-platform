#!/usr/bin/env python
import os
import sys
import unittest
from pathlib import Path


SPIKE_ROOT = Path(__file__).resolve().parents[1]
os.chdir(SPIKE_ROOT)
sys.path.insert(0, str(SPIKE_ROOT))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django

django.setup()

if len(sys.argv) > 1:
    suite = unittest.defaultTestLoader.loadTestsFromNames(sys.argv[1:])
else:
    suite = unittest.defaultTestLoader.discover(str(SPIKE_ROOT / "tests"))
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(not result.wasSuccessful())
