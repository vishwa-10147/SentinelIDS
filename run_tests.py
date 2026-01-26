"""
Test Runner Script
Run all unit tests for IoT IDS ML Dashboard
"""

import subprocess
import sys
import os


def run_tests():
    """Run all unit tests"""
    print("=" * 60)
    print("IoT IDS ML Dashboard - Unit Test Suite")
    print("=" * 60)
    print()
    
    # Change to project root
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Run pytest
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
        cwd=os.getcwd()
    )
    
    print()
    print("=" * 60)
    if result.returncode == 0:
        print("✅ All tests passed!")
    else:
        print("❌ Some tests failed!")
    print("=" * 60)
    
    return result.returncode


if __name__ == "__main__":
    sys.exit(run_tests())
