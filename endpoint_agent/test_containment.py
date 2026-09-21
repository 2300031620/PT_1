"""
Unit tests for Endpoint Safe Containment Module
Verifies:
1. Containment activation on CRITICAL severity
2. Device marked as CONTAINED
3. Reason recorded
4. Timestamp recorded
5. Containment release restoration
"""

import os
import sys
import unittest
from pathlib import Path

# Ensure directory is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from containment import SafeContainmentManager
except ImportError:
    from endpoint_agent.containment import SafeContainmentManager

class TestContainment(unittest.TestCase):
    def setUp(self):
        self.manager = SafeContainmentManager(device_id="TEST-PC-01")
        # Ensure clean state
        self.manager.release_device()

    def tearDown(self):
        self.manager.release_device()

    def test_contain_device(self):
        reason = "Suspicious extension changes detected (.locked)"
        res = self.manager.contain_device(reason=reason, operator="Automated Rule Engine", role="admin")

        self.assertTrue(self.manager.is_contained)
        self.assertEqual(res["status"], "CONTAINED")
        self.assertEqual(res["device_id"], "TEST-PC-01")
        self.assertEqual(res["containment_reason"], reason)
        self.assertIsNotNone(res["contained_at"])

        status = self.manager.get_status()
        self.assertTrue(status["is_contained"])
        self.assertEqual(status["containment_reason"], reason)

    def test_release_device(self):
        self.manager.contain_device(reason="Ransomware burst", operator="Rule Engine")
        self.assertTrue(self.manager.is_contained)

        rel = self.manager.release_device(operator="Security Admin", role="admin")
        self.assertFalse(self.manager.is_contained)
        self.assertEqual(rel["status"], "PROTECTED")
        self.assertIsNone(self.manager.containment_reason)
        self.assertIsNone(self.manager.contained_at)

if __name__ == "__main__":
    unittest.main()
