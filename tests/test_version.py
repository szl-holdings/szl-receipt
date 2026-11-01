"""Installed/editable package runtime and distribution versions must agree."""
from importlib.metadata import version

import szl_receipt


def test_runtime_version_matches_distribution_metadata():
    assert szl_receipt.__version__ == version("szl-receipt-dsse")
