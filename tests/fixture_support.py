"""Temporary, synthetic-only fixtures shared by the offline test suite."""
from pathlib import Path
import shutil
import tempfile
from uuid import uuid4


def fixture_directory(test_case, label):
    """Allocate outside the checkout and register cleanup before test work."""
    boundary = Path(tempfile.gettempdir()).resolve()
    root = boundary / ("campus-tests-" + label + "-" + uuid4().hex)
    if root.parent != boundary:
        raise ValueError("Fixture label must not contain a directory separator")
    # Path.mkdir inherits Windows ACLs. Python 3.14 TemporaryDirectory's 0700
    # ACL can exclude a restricted test runner; these files contain fake data.
    root.mkdir()
    test_case.addCleanup(shutil.rmtree, root)
    return root
