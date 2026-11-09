// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <string>

#include "latchkey_util/secret_pattern.h"

void setUp() {}

void tearDown() {}

static void test_real_log_lines_pass() {
    const char* lines[] = {
        "HTTPS certificate SHA-256 3A:4F:9C:D2:11:07:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:"
        "45:67:89:AB:CD",
        "features 0x0000000000ffbfff",
        "seen 00:00:5E:00:53:01: public address, advert type 0, rssi -61, protocol 5.3 scene 2, paired, battery 57",
        "link to 00:00:5E:00:53:01 (public address): mtu 247, write characteristic properties 0x0c, writes with "
        "response",
        "latchkey 0.2.0 board=esp32s3-atom chip=esp32s3 idf=v6.1.0",
        "owner password hashed with 4400 iterations in 1153 ms",
        "connected, ip 192.0.2.62",
        "SNTP synced, utc 1794146587",
        "mode : sta (00:00:5e:00:53:02)",
        "paired: time calibrated, admin passcode confirmed, 0 frames dropped",
        "new P-256 key and self-signed certificate (418 bytes) in 2140 ms",
        "phy_version 4863,a3a4459,Oct 28 2024,14:30:06",
        "event socket 54 does not take frames: closing it",
        "the secret of good logging is short lines",
        "the totp step was already used",
        "a password must be 12 to 128 bytes",
        "ABCDEFGHIJKLMNOP QRSTUVWXYZ234567 ABCDEFGHIJKLMNOPQRSTUVWXYZ2345",
    };
    for (const char* line : lines) {
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::holdsSecretPattern(line), line);
    }
}

static void test_an_otpauth_uri_is_caught() {
    TEST_ASSERT_TRUE(latchkey_util::holdsSecretPattern(
        "reply otpauth://totp/Latchkey:esp32s3-atom?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Latchkey"));
    TEST_ASSERT_TRUE(latchkey_util::holdsSecretPattern("OTPAUTH://TOTP/x"));
}

static void test_a_secret_parameter_is_caught() {
    TEST_ASSERT_TRUE(latchkey_util::holdsSecretPattern("uri ?secret=JBSWY3DP&issuer=x"));
    TEST_ASSERT_TRUE(latchkey_util::holdsSecretPattern("Secret=abc"));
}

static void test_a_session_cookie_is_caught() {
    TEST_ASSERT_TRUE(latchkey_util::holdsSecretPattern("Cookie: lk_session=abc"));
}

static void test_long_hex_runs_are_caught() {
    const std::string key(32, 'a');
    TEST_ASSERT_TRUE(latchkey_util::holdsSecretPattern("aes key " + key));
    TEST_ASSERT_TRUE(latchkey_util::holdsSecretPattern("token=" + std::string(64, 'F') + " end"));
    TEST_ASSERT_TRUE(latchkey_util::holdsSecretPattern("0123456789abcdef0123456789ABCDEF"));
    TEST_ASSERT_FALSE(latchkey_util::holdsSecretPattern("almost " + std::string(31, 'a')));
}

static void test_long_base32_runs_are_caught() {
    TEST_ASSERT_TRUE(latchkey_util::holdsSecretPattern("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"));
    TEST_ASSERT_TRUE(latchkey_util::holdsSecretPattern("x=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPQ;"));
    TEST_ASSERT_FALSE(latchkey_util::holdsSecretPattern("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX"));
}

static void test_json_members_holding_secrets_are_caught() {
    const char* lines[] = {
        "request {\"password\":\"hunter2 hunter2\"}",
        "{\"totp\": \"123456\"}",
        "{\"passphrase\":\"x\"}",
        "{\"adminPasscode\":\"1234567\"}",
        "{\"current\":\"a\",\"new\":\"b\"}",
        "{\"new\" : \"b\"}",
        "{\"backup\":\"TEtCMgE\"}",
        "{\"code\":\"123456\"}",
        "{\"otpauth\":\"x\"}",
    };
    for (const char* line : lines) {
        TEST_ASSERT_TRUE_MESSAGE(latchkey_util::holdsSecretPattern(line), line);
    }
    TEST_ASSERT_FALSE(latchkey_util::holdsSecretPattern("{\"code\":\"busy\",\"message\":\"try again\"}"));
    TEST_ASSERT_FALSE(latchkey_util::holdsSecretPattern("{\"passwordSet\":true}"));
    TEST_ASSERT_FALSE(latchkey_util::holdsSecretPattern("the new password is stored"));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_real_log_lines_pass);
    RUN_TEST(test_an_otpauth_uri_is_caught);
    RUN_TEST(test_a_secret_parameter_is_caught);
    RUN_TEST(test_a_session_cookie_is_caught);
    RUN_TEST(test_long_hex_runs_are_caught);
    RUN_TEST(test_long_base32_runs_are_caught);
    RUN_TEST(test_json_members_holding_secrets_are_caught);
    return UNITY_END();
}
