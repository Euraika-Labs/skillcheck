#!/usr/bin/env python3
"""Read the project config and print the active profile."""
import json
from pathlib import Path

config = json.loads(Path("config.json").read_text())
print(config.get("profile", "default"))
