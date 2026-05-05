#!/usr/bin/env python3
"""
TEST RUNNER: Execute all tests and generate comprehensive reports.
Run this script to perform 5.1, 5.2, and 5.3 testing.

Usage:
    python run_all_tests.py
"""

import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path


def run_command(cmd, description):
    """Run a command and return success status."""
    print(f"\n{'='*70}")
    print(f"▶ {description}")
    print(f"{'='*70}")
    print(f"Command: {' '.join(cmd)}\n")
    
    result = subprocess.run(cmd, capture_output=False)
    
    if result.returncode != 0:
        print(f"\n✗ {description} FAILED")
        return False
    
    print(f"\n✓ {description} PASSED")
    return True


def main():
    """Run all tests and generate reports."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = Path("test_reports")
    report_dir.mkdir(exist_ok=True)
    
    print("\n" + "="*70)
    print(" DAXD ADAPTIVE AGENTIC HONEYPOT - COMPREHENSIVE TEST SUITE")
    print("="*70)
    print(f"\nTimestamp: {timestamp}")
    print(f"Report Directory: {report_dir}")
    
    all_passed = True
    
    # 5.1 BLACK BOX TESTING
    print("\n\n" + "█"*70)
    print("█ 5.1 BLACK BOX TESTING")
    print("█"*70)
    
    pytest_args_blackbox = [
        "pytest", "tests/",
        "-m", "blackbox",
        "-v",
        f"--html={report_dir}/5.1_blackbox_report.html",
        "--self-contained-html",
        "--tb=short"
    ]
    
    all_passed &= run_command(
        pytest_args_blackbox,
        "5.1 Black Box Testing (End-to-End & Integration Tests)"
    )
    
    # 5.2 WHITE BOX TESTING
    print("\n\n" + "█"*70)
    print("█ 5.2 WHITE BOX TESTING")
    print("█"*70)
    
    pytest_args_whitebox = [
        "pytest", "tests/",
        "-m", "whitebox",
        "-v",
        f"--html={report_dir}/5.2_whitebox_report.html",
        "--self-contained-html",
        "--tb=short"
    ]
    
    all_passed &= run_command(
        pytest_args_whitebox,
        "5.2 White Box Testing (Unit Tests)"
    )
    
    # 5.3 TEST COVERAGE
    print("\n\n" + "█"*70)
    print("█ 5.3 TEST COVERAGE ANALYSIS")
    print("█"*70)
    
    coverage_args = [
        "pytest", "tests/",
        f"--cov=.",
        "--cov-report=html:test_reports/5.3_coverage_html",
        "--cov-report=term-missing",
        f"--html={report_dir}/5.3_coverage_report.html",
        "--self-contained-html",
        "-v",
        "--tb=short"
    ]
    
    all_passed &= run_command(
        coverage_args,
        "5.3 Test Coverage Analysis (coverage.py)"
    )
    
    # COMPLETE TEST SUITE
    print("\n\n" + "█"*70)
    print("█ COMPLETE TEST SUITE (All Tests)")
    print("█"*70)
    
    all_tests_args = [
        "pytest", "tests/",
        "-v",
        f"--html={report_dir}/complete_test_report.html",
        "--self-contained-html",
        f"--cov=.",
        "--cov-report=term-missing",
        f"--cov-report=html:test_reports/complete_coverage_html",
        "--tb=short"
    ]
    
    all_passed &= run_command(
        all_tests_args,
        "Complete Test Suite Execution"
    )
    
    # Generate Summary Report
    print("\n\n" + "="*70)
    print(" TEST EXECUTION SUMMARY")
    print("="*70)
    
    generate_summary_report(timestamp, report_dir, all_passed)
    
    print("\n\n" + "="*70)
    print(" AVAILABLE REPORTS")
    print("="*70)
    print(f"""
    📊 Test Reports Location: {report_dir.absolute()}
    
    Reports Generated:
    ✓ 5.1_blackbox_report.html        - Black Box Testing Results
    ✓ 5.2_whitebox_report.html        - White Box Testing Results  
    ✓ 5.3_coverage_report.html        - Coverage Analysis Report
    ✓ complete_test_report.html       - Combined Test Results
    ✓ test_summary_{timestamp}.txt    - Summary Report
    ✓ 5.3_coverage_html/              - Detailed Coverage HTML
    ✓ complete_coverage_html/         - Complete Coverage HTML
    
    Open in browser:
    • test_reports/5.1_blackbox_report.html
    • test_reports/5.2_whitebox_report.html
    • test_reports/complete_test_report.html
    """)
    
    # Exit status
    if all_passed:
        print("\n✅ ALL TESTS COMPLETED SUCCESSFULLY!")
        return 0
    else:
        print("\n❌ SOME TESTS FAILED. Review reports above.")
        return 1


def generate_summary_report(timestamp, report_dir, all_passed):
    """Generate a summary report file."""
    summary_file = report_dir / f"test_summary_{timestamp}.txt"
    
    status = "PASSED" if all_passed else "FAILED"
    
    summary = f"""
{'='*70}
DAXD - ADAPTIVE AGENTIC HONEYPOT TESTING SUMMARY
{'='*70}

Execution Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Timestamp: {timestamp}
Overall Status: {status}

{'='*70}
TESTING BREAKDOWN
{'='*70}

5.1 BLACK BOX TESTING
    ├─ Type: End-to-End & Integration Testing
    ├─ Purpose: Test system from user perspective
    ├─ Framework: pytest with blackbox marker
    ├─ Coverage: App, Database, LLM, Graph modules
    └─ Report: 5.1_blackbox_report.html

5.2 WHITE BOX TESTING
    ├─ Type: Unit & Module Testing
    ├─ Purpose: Test internal logic and code paths
    ├─ Framework: pytest with whitebox marker
    ├─ Coverage: database.py, llm_config.py, graph.py
    └─ Report: 5.2_whitebox_report.html

5.3 TEST COVERAGE ANALYSIS
    ├─ Tool: coverage.py
    ├─ Metrics: Line, Branch, Function coverage
    ├─ Format: HTML report + Terminal summary
    ├─ Location: 5.3_coverage_html/
    └─ Report: 5.3_coverage_report.html

{'='*70}
TEST EXECUTION COMMANDS
{'='*70}

Run Black Box Tests Only:
  pytest tests/ -m blackbox -v --html=test_reports/blackbox.html

Run White Box Tests Only:
  pytest tests/ -m whitebox -v --html=test_reports/whitebox.html

Run Coverage Analysis:
  pytest tests/ --cov=. --cov-report=html --cov-report=term-missing

Run All Tests:
  python run_all_tests.py

{'='*70}
TEST FILES STRUCTURE
{'='*70}

tests/
├── __init__.py              - Test package marker
├── conftest.py              - Pytest configuration & fixtures
├── test_database.py         - White box: Database module
├── test_llm_config.py       - White box: LLM configuration
├── test_graph.py            - White box: Graph & agents
├── test_app.py              - Black box: Streamlit app
└── test_integration.py      - Black box: Integration tests

{'='*70}
TOOLS & TECHNOLOGIES USED
{'='*70}

Black Box Testing Tools:
  ✓ pytest                   - Test framework
  ✓ pytest-html              - HTML reporting
  ✓ unittest.mock            - Mocking dependencies
  ✓ Streamlit testing lib    - App testing

White Box Testing Tools:
  ✓ pytest                   - Test framework
  ✓ pytest-mock              - Mock fixtures
  ✓ pytest-asyncio           - Async support
  ✓ inspect/introspection    - Code analysis

Coverage Tools:
  ✓ coverage.py              - Line & branch coverage
  ✓ pytest-cov               - Coverage plugin
  ✓ HTML reporting           - Visual reports

{'='*70}
NEXT STEPS
{'='*70}

1. Review black box reports for user-facing functionality
2. Review white box reports for internal logic coverage
3. Analyze coverage reports for gaps
4. Address any failing tests
5. Integrate into CI/CD pipeline

{'='*70}
"""
    
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write(summary)
    
    print(f"\n✓ Summary report saved: {summary_file}")


if __name__ == "__main__":
    sys.exit(main())
