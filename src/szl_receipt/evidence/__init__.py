# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
# ORCID: 0009-0001-0110-4173
"""Typed evidence layer: claims, inventory, and the read-only service.

This subpackage is stdlib-only on purpose: the evidence service must be
deployable into the most constrained runtimes (GitHub Pages data build,
a HF Space container) without extending the frozen dependency graph of
``szl-receipt-dsse``. It composes with, but does not require, the DSSE
receipt stack: a claim's ``evidence_uri`` may point at a signed receipt
envelope, a CI run manifest, or an HF artifact — the claim layer checks
shape, the receipt layer provides cryptographic verification.
"""
from .claims import (
    ALL_STATUSES,
    MEASURED,
    MISSING,
    REPRODUCED,
    REQUIRED_CLAIM_SLOTS,
    SELF_ASSERTED,
    VERIFIED_STATUSES,
    Claim,
    ClaimValidationError,
    is_valid_digest,
    is_valid_utc_timestamp,
)
from .inventory import (
    CLASSIFICATIONS,
    FULLY_EVIDENCED,
    INVENTORY_ONLY,
    PARTIALLY_EVIDENCED,
    EvidenceInventory,
    InventoryLoadError,
    ModelEvidence,
)
from .service import EvidenceService, build_server, make_handler

__all__ = [
    "Claim",
    "ClaimValidationError",
    "MEASURED",
    "REPRODUCED",
    "SELF_ASSERTED",
    "MISSING",
    "ALL_STATUSES",
    "VERIFIED_STATUSES",
    "REQUIRED_CLAIM_SLOTS",
    "is_valid_digest",
    "is_valid_utc_timestamp",
    "ModelEvidence",
    "EvidenceInventory",
    "InventoryLoadError",
    "CLASSIFICATIONS",
    "FULLY_EVIDENCED",
    "PARTIALLY_EVIDENCED",
    "INVENTORY_ONLY",
    "EvidenceService",
    "build_server",
    "make_handler",
]
