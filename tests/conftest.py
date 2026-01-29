"""
Global test fixtures.

Overrides authentication for all tests so unit tests don't
require auth credentials or a running auth service.
"""

import os

# Disable auth before any app imports
os.environ["AUTH_ENABLED"] = "false"
