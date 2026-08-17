from __future__ import annotations

from support import TestFunc
from test_hardening_behaviors import TESTS as HARDENING_TESTS
from test_remediation_behaviors import TESTS as REMEDIATION_TESTS
from test_report_behaviors import TESTS as REPORT_TESTS
from test_scan_behaviors import TESTS as SCAN_TESTS
from test_matcher_gate import TESTS as MATCHER_GATE_TESTS
from test_secrets_behaviors import TESTS as SECRETS_TESTS
from test_deps_behaviors import TESTS as DEPS_TESTS
from test_feed_sca_behaviors import TESTS as FEED_SCA_TESTS
from test_enterprise_behaviors import TESTS as ENTERPRISE_TESTS
from test_cli_contract import TESTS as CLI_TESTS


def all_tests() -> list[TestFunc]:
    return [
        *SCAN_TESTS,
        *REPORT_TESTS,
        *REMEDIATION_TESTS,
        *HARDENING_TESTS,
        *MATCHER_GATE_TESTS,
        *SECRETS_TESTS,
        *DEPS_TESTS,
        *FEED_SCA_TESTS,
        *ENTERPRISE_TESTS,
        *CLI_TESTS,
    ]


def main() -> int:
    for test in all_tests():
        test()
        print(f"PASS {test.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
