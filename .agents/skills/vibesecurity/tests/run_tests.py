from __future__ import annotations

from support import TestFunc
from test_remediation_behaviors import TESTS as REMEDIATION_TESTS
from test_report_behaviors import TESTS as REPORT_TESTS
from test_scan_behaviors import TESTS as SCAN_TESTS


def all_tests() -> list[TestFunc]:
    return [*SCAN_TESTS, *REPORT_TESTS, *REMEDIATION_TESTS]


def main() -> int:
    for test in all_tests():
        test()
        print(f"PASS {test.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
