# SPDX-License-Identifier: GPL-3.0-or-later
import configparser
import unittest
from pathlib import Path


class BoardConfigTest(unittest.TestCase):
    def test_s3_default_is_board_neutral_and_keeps_gpio_zero(self):
        config = configparser.ConfigParser(interpolation=None)
        config.read(Path(__file__).resolve().parents[2] / "platformio.ini")
        flags = config["env:esp32s3"]["build_flags"].split()
        self.assertIn('-DLATCHKEY_BOARD=\\"esp32s3\\"', flags)
        self.assertIn("-DLATCHKEY_BUTTON_GPIO=0", flags)


if __name__ == "__main__":
    unittest.main()
