# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.engine.options import ReviewOptions, coerce_review_options


def test_review_options_normalizes_mode():
    assert ReviewOptions(review_mode="AGENTIC").review_mode == "agentic"


def test_review_options_rejects_unknown_mode():
    with pytest.raises(ValueError, match="Unsupported review mode"):
        ReviewOptions(review_mode="typo")


def test_coerce_review_options_validates_existing_options():
    options = ReviewOptions.__new__(ReviewOptions)
    object.__setattr__(options, "use_retrieval_context", True)
    object.__setattr__(options, "review_mode", "typo")
    object.__setattr__(options, "agentic", ReviewOptions().agentic)

    with pytest.raises(ValueError, match="Unsupported review mode"):
        coerce_review_options(options)
