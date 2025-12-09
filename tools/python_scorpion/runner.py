import os
import sys

# Ensure src-based package is importable when building/running locally
_HERE = os.path.dirname(__file__)
_SRC = os.path.join(_HERE, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from python_scorpion.cli import app

if __name__ == "__main__":
    app()
