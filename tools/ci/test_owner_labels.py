# SPDX-License-Identifier: GPL-3.0-or-later
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(TOOLS / "hil"))

from owner import claims, otpauth_secret, totp_code


def uri(board: str) -> str:
    return (
        f"otpauth://totp/Latchkey:{board}?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        "&issuer=Latchkey&algorithm=SHA1&digits=6&period=30"
    )


class OwnerLabelsTest(unittest.TestCase):
    def tearDown(self):
        claims.clear()

    def test_issued_s3_label_remains_usable_after_generic_board_rename(self):
        legacy = otpauth_secret(uri("esp32s3-atom"), "esp32s3")
        current = otpauth_secret(uri("esp32s3"), "esp32s3")
        self.assertEqual(totp_code(legacy, 59), totp_code(current, 59))

    def test_unrelated_board_labels_are_still_rejected(self):
        for issued, expected in [("esp32-devkit", "esp32s3"), ("other-s3", "esp32s3"), ("esp32s3-atom", "esp32-devkit")]:
            with self.subTest(issued=issued, expected=expected), self.assertRaises(AssertionError):
                otpauth_secret(uri(issued), expected)


if __name__ == "__main__":
    unittest.main()
