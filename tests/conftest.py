# -*- coding: utf-8 -*-
"""Make ``src/`` and this folder importable when running the tests in place."""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _path in (os.path.join(_ROOT, "src"), _HERE):
    if _path not in sys.path:
        sys.path.insert(0, _path)
