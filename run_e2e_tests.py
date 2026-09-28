#!/usr/bin/env python
import os
import sys

import django
from django.conf import settings
from django.test.utils import get_runner

if __name__ == "__main__":
    os.environ["DJANGO_SETTINGS_MODULE"] = "tests.e2e.settings"
    django.setup()
    E2eTestRunner = get_runner(settings)
    test_runner = E2eTestRunner()
    failures = test_runner.run_tests(["tests/e2e"])
    # custom summary
    print("\n" + "=" * 70)
    print("    E2E TEST SUITES SUMMARY")
    print("\n" + "=" * 70)
    if failures:
        print(f"FAILED: {failures} test(s) failed")
    else:
        print("SUCCESS: All tests passed")
    print("=" * 70)
    sys.exit(bool(failures))
