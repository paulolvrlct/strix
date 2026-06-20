from __future__ import annotations

import sys
from pathlib import Path

# Ensure the src/ layout is importable when running pytest without an editable install.
SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
