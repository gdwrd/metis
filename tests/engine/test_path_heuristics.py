# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.engine.path_heuristics import is_test_path


@pytest.mark.parametrize(
    "path",
    [
        "tests/foo.py",
        "src/test/foo.py",
        "src/__tests__/component.tsx",
        "pkg/foo_test.go",
        "pkg/test_foo.py",
        "pkg/foo.spec.ts",
        "pkg/foo.test.jsx",
        "src/FooTest.java",
        "src/FooTests.cs",
        "spec/models/user_spec.rb",
        "juliet/testcases/CWE121/stack_overflow.c",
        "org/owasp/benchmark/BenchmarkTest00001.java",
    ],
)
def test_is_test_path_matches_default_test_and_fixture_patterns(path):
    assert is_test_path(path)


@pytest.mark.parametrize(
    "path",
    [
        "src/app.py",
        "srctests/foo.py",
        "contest/foo.py",
        "src/testdata/parser.go",
        "src/prod_specification.ts",
        "src/BenchmarkTester.java",
    ],
)
def test_is_test_path_avoids_substring_false_positives(path):
    assert not is_test_path(path)


def test_is_test_path_accepts_extra_patterns():
    assert is_test_path("fixtures/vulnerable.c", extra_patterns=["fixtures/**"])
    assert not is_test_path("fixtures/vulnerable.c")
