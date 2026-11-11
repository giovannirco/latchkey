# SPDX-License-Identifier: GPL-3.0-or-later
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import mock_api


class MockContractTest(unittest.TestCase):
    def setUp(self):
        self.mock = mock_api.Mock()
        self.mock.sessions["fixture"] = time.time()
        self.context = mock_api.Context("fixture")

    def tearDown(self):
        self.mock.reset()

    def call(self, method, params=None):
        return self.mock.dispatch(method, params or {}, self.context)

    def test_battery_alert_deduplicates_until_recovery_even_after_acknowledgement(self):
        lock = self.mock.locks[mock_api.FRONT_DOOR]
        self.mock.observe_battery(lock, 40)
        self.assertEqual(lock["alerts"], [])
        self.mock.observe_battery(lock, 39)
        self.assertEqual(lock["alerts"][0]["kind"], "low_battery")
        self.assertEqual(lock["alerts"][0]["battery"], 39)
        self.call("lock.alerts.ack", {"lock": lock["id"], "through": 1})
        self.mock.observe_battery(lock, 30)
        self.assertEqual(lock["alerts"], [])
        self.mock.observe_battery(lock, 40)
        self.mock.observe_battery(lock, 0)
        self.assertEqual(lock["alerts"][0]["id"], 2)
        self.mock.observe_battery(lock, 100)
        self.assertEqual(lock["alerts"], [])

    def test_alert_overflow_preserves_an_unacknowledged_battery_warning(self):
        lock = self.mock.locks[mock_api.FRONT_DOOR]
        self.mock.observe_battery(lock, 39)
        for seq in range(1, 10):
            self.mock.emit("lock.alert", {
                "lock": lock["id"], "method": "app", "time": seq, "seq": seq, "type": 1,
            })
        self.assertEqual(len(lock["alerts"]), 8)
        self.assertEqual(lock["alerts"][0]["kind"], "low_battery")
        self.assertEqual([alert["seq"] for alert in lock["alerts"][1:]], list(range(3, 10)))
        self.mock.observe_battery(lock, 20)
        self.assertEqual(len(lock["alerts"]), 8)
        self.mock.observe_battery(lock, 40)
        self.assertEqual(len(lock["alerts"]), 7)
        self.assertTrue(all(alert["kind"] == "unexpected_unlock" for alert in lock["alerts"]))

    def test_log_tracks_added_and_deleted_credentials_without_pin_digits(self):
        self.mock.config.latency_ms = 0
        target = {"lock": mock_api.FRONT_DOOR}
        added = self.mock.lock_passcodes_add(self.context, {**target, "type": "permanent", "name": "Visitor", "code": "483927"})
        item_id = added["passcode"]["id"]
        self.mock.lock_passcodes_delete(self.context, {**target, "id": item_id})
        result = self.mock.lock_log_fetch(self.context, target)
        events = result["entries"][-2:]
        self.assertEqual([entry["action"] for entry in events], ["add", "delete"])
        self.assertEqual([entry["credential"]["name"] for entry in events], ["Visitor", "Visitor"])
        self.assertEqual(events[-1]["credential"]["nameSource"], "last_known_label")
        self.assertTrue("483927" not in str(result))
        card = self.mock.locks[mock_api.FRONT_DOOR]["cards"][0]
        self.mock.lock_cards_delete(self.context, {**target, "id": card["id"]})
        event = self.mock.lock_log_fetch(self.context, target)["entries"][-1]
        self.assertEqual(event["credential"]["name"], card["name"])
        self.assertEqual(event["credential"]["kind"], "card")

    def test_log_classifies_every_supported_failed_attempt(self):
        lock = self.mock.locks[mock_api.FRONT_DOOR]
        for kind in [7, 11, 12, 13, 22, 25, 38, 39, 40, 41]:
            with self.subTest(kind=kind):
                event = self.mock.log_entry(lock, {"seq": 1, "time": 0, "type": kind, "battery": 80})
                self.assertEqual(event["action"], "unlock")
                self.assertEqual(event["outcome"], "failure")

    def test_timezone_roundtrip_and_system_info_share_the_saved_zone(self):
        self.assertEqual(self.call("system.timezone.get"), {"tz": "UTC0", "utcOffset": 0})
        self.assertEqual(
            self.call("system.timezone.set", {"tz": "<-03>3"}),
            {"tz": "<-03>3", "utcOffset": -10800},
        )
        info = self.call("system.info")
        self.assertEqual(info["timezone"], "<-03>3")
        self.assertTrue(info["localTime"].endswith("-03:00"))
        self.assertEqual(self.call("system.timezone.get")["tz"], "<-03>3")

    def test_timezone_validation_rejects_iana_names_missing_rules_and_bad_ranges(self):
        for value in [
            "America/New_York",
            "CET-1CEST",
            "UTC24",
            "UTC-24",
            "UTC1:60",
            "UTC0:00:01",
            "UTC0 ",
            "A0",
            "UTC0DST,M13.1.0,M10.1.0",
            "UTC0DST,M3.1.0/167:01,M10.1.0",
            None,
            3,
        ]:
            with (
                self.subTest(value=value),
                self.assertRaises(mock_api.RpcError) as raised,
            ):
                self.call("system.timezone.set", {"tz": value})
            self.assertEqual(raised.exception.code, "invalid_argument")
        self.assertEqual(self.call("system.timezone.get")["tz"], "UTC0")

    def test_timezone_uses_explicit_daylight_rules_and_unsynced_offset_is_null(self):
        self.call("system.timezone.set", {"tz": "EST5EDT,M3.2.0,M11.1.0"})
        for instant, offset, local in [
            (1768478400, -18000, "2026-01-15T07:00:00-05:00"),
            (1784116800, -14400, "2026-07-15T08:00:00-04:00"),
        ]:
            with (
                self.subTest(instant=instant),
                patch.object(mock_api, "now", return_value=instant),
            ):
                self.assertEqual(self.call("system.timezone.get")["utcOffset"], offset)
                self.assertEqual(self.call("system.info")["localTime"], local)
        self.mock.config.time_synced = False
        self.assertIsNone(self.call("system.timezone.get")["utcOffset"])
        info = self.call("system.info")
        self.assertIsNone(info["time"]["utc"])
        self.assertIsNone(info["localTime"])

    def test_timezone_rule_ranges_and_leading_zeroes_follow_firmware(self):
        for rule in ["J0", "J366", "366", "M0.1.0", "M3.0.0", "M3.6.0", "M3.1.7"]:
            with self.subTest(rule=rule), self.assertRaises(mock_api.RpcError):
                self.call("system.timezone.set", {"tz": f"UTC0DST,{rule},M11.1.0"})
        for tz in [
            "UTC00",
            "UTC0DST,J001,J365",
            "UTC0DST,000,365",
            "UTC0DST,M03.1.0/001,M11.1.0",
        ]:
            with self.subTest(tz=tz):
                self.assertEqual(self.call("system.timezone.set", {"tz": tz})["tz"], tz)

    def test_audit_limit_and_next_match_firmware(self):
        self.mock.audit = [{"seq": index} for index in range(1, 61)]
        first = self.call("audit.list", {"limit": 50})
        self.assertEqual(len(first["entries"]), 50)
        self.assertTrue(first["more"])
        self.assertEqual(first["next"], 11)
        last = self.call("audit.list", {"before": first["next"]})
        self.assertEqual([entry["seq"] for entry in last["entries"]], list(range(10, 0, -1)))
        self.assertFalse(last["more"])
        self.assertIsNone(last["next"])
        for limit in [0, 51, None, True]:
            with self.subTest(limit=limit), self.assertRaises(mock_api.RpcError):
                self.call("audit.list", {"limit": limit})

    def test_reboot_and_reset_return_empty_results(self):
        self.assertEqual(self.call("system.reboot"), {})
        self.mock.config.confirm_delay_ms = 0
        self.assertEqual(self.mock.system_factory_reset(self.context, {}), {})

    def test_system_and_lock_summaries_include_firmware_diagnostics(self):
        info = self.call("system.info")
        self.assertEqual(info["firmware"], "0.7.0")
        for field in ["claimed", "button", "ble", "nvs", "stackFree"]:
            self.assertIn(field, info)
        self.assertIn("largestBlock", info["heap"])
        lock = self.call("locks.list")["locks"][0]
        self.assertTrue(lock["pairComplete"])
        self.assertTrue(lock["adminPasscodeConfirmed"])

    def test_reset_disable_changes_refusal_after_backup_without_switch_mutation(self):
        lock = self.mock.locks[mock_api.FRONT_DOOR]
        original = lock["resetButton"]
        for backed_up, code in [(False, "backup_required"), (True, "unverified")]:
            lock["backedUp"] = backed_up
            with self.assertRaises(mock_api.RpcError) as raised:
                self.mock.lock_reset_button_set(self.context, {"lock": mock_api.FRONT_DOOR, "enabled": False})
            self.assertEqual(raised.exception.code, code)
            self.assertEqual(lock["resetButton"], original)

    def test_autolock_without_reported_range_accepts_protocol_limits(self):
        self.mock.config.latency_ms = 0
        lock = self.mock.locks[mock_api.FRONT_DOOR]
        for minimum, maximum in [(None, None), (5, None), (None, 20)]:
            lock["autolock"] = {"seconds": 0, "min": minimum, "max": maximum}
            for seconds in [0, 1, 65535]:
                with self.subTest(minimum=minimum, maximum=maximum, seconds=seconds):
                    result = self.mock.lock_autolock_set(
                        self.context, {"lock": mock_api.FRONT_DOOR, "seconds": seconds}
                    )
                    self.assertEqual(result["seconds"], seconds)
            for seconds in [-1, 65536, None, True]:
                with self.subTest(seconds=seconds), self.assertRaises(mock_api.RpcError):
                    self.mock.lock_autolock_set(self.context, {"lock": mock_api.FRONT_DOOR, "seconds": seconds})

    def test_passage_rejects_more_than_eight_days_before_mutating(self):
        self.mock.config.latency_ms = 0
        params = {"lock": mock_api.FRONT_DOOR, "type": "weekly", "start": "10:00", "end": "11:00"}
        before = list(self.mock.locks[mock_api.FRONT_DOOR]["passage"])
        with self.assertRaises(mock_api.RpcError) as raised:
            self.mock.lock_passage_add(self.context, {**params, "days": [1] * 9})
        self.assertEqual(raised.exception.code, "invalid_argument")
        self.assertEqual(self.mock.locks[mock_api.FRONT_DOOR]["passage"], before)
        result = self.mock.lock_passage_add(self.context, {**params, "days": list(range(8))})
        self.assertEqual(len(result["modes"]), len(before) + 8)


if __name__ == "__main__":
    unittest.main()
