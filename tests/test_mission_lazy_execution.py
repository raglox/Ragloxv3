"""
Updated shell execution tests - simulation mode removed.

All previous tests expecting SIMULATION MODE are skipped as that feature
was removed from the codebase. The current behavior returns error messages
about environment not being available instead of simulation output.
"""
import pytest

# Mark all tests in old file as skipped
pytestmark = pytest.mark.skip(reason="Simulation mode removed - tests need rewrite")
