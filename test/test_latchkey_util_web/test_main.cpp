// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

#include <cstdint>
#include <optional>
#include <string>

#include "latchkey_util/web.h"

void setUp() {}

void tearDown() {}

static void test_json_content_types_are_recognised() {
    TEST_ASSERT_TRUE(latchkey_util::isJsonContentType("application/json"));
    TEST_ASSERT_TRUE(latchkey_util::isJsonContentType("application/json; charset=utf-8"));
    TEST_ASSERT_TRUE(latchkey_util::isJsonContentType("application/json;charset=UTF-8"));
    TEST_ASSERT_TRUE(latchkey_util::isJsonContentType("Application/JSON"));
    TEST_ASSERT_TRUE(latchkey_util::isJsonContentType(" application/json \t"));
}

static void test_other_content_types_are_refused() {
    TEST_ASSERT_FALSE(latchkey_util::isJsonContentType(""));
    TEST_ASSERT_FALSE(latchkey_util::isJsonContentType("text/plain"));
    TEST_ASSERT_FALSE(latchkey_util::isJsonContentType("application/jsonx"));
    TEST_ASSERT_FALSE(latchkey_util::isJsonContentType("application/json-patch+json"));
    TEST_ASSERT_FALSE(latchkey_util::isJsonContentType("application/x-www-form-urlencoded"));
    TEST_ASSERT_FALSE(latchkey_util::isJsonContentType("multipart/form-data; boundary=application/json"));
}

static void test_firmware_uploads_are_octet_streams() {
    TEST_ASSERT_TRUE(latchkey_util::isOctetStreamContentType("application/octet-stream"));
    TEST_ASSERT_TRUE(latchkey_util::isOctetStreamContentType("Application/Octet-Stream"));
    TEST_ASSERT_TRUE(latchkey_util::isOctetStreamContentType(" application/octet-stream ; x=1"));
    TEST_ASSERT_FALSE(latchkey_util::isOctetStreamContentType(""));
    TEST_ASSERT_FALSE(latchkey_util::isOctetStreamContentType("application/json"));
    TEST_ASSERT_FALSE(latchkey_util::isOctetStreamContentType("multipart/form-data; boundary=application/octet-stream"));
    TEST_ASSERT_FALSE(latchkey_util::isOctetStreamContentType("text/plain"));
}

static constexpr uint32_t kBoard = 0xC000023F;

static void test_the_board_address_is_its_own_host() {
    TEST_ASSERT_TRUE(latchkey_util::isOwnHost("192.0.2.63", kBoard));
    TEST_ASSERT_TRUE(latchkey_util::isOwnHost("192.0.2.63:443", kBoard));
}

static void test_other_hosts_are_not_the_board() {
    const char* refused[] = {
        "192.0.2.64", "192.0.2.63:8443", "192.0.2.63:", "192.000.2.63", "latchkey.example", "rebind.attacker.example",
        "192.0.2.63.attacker.example", "", ":443", "[2001:db8::1]",
    };
    for (const char* host : refused) {
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::isOwnHost(host, kBoard), host);
    }
    TEST_ASSERT_FALSE(latchkey_util::isOwnHost("0.0.0.0", 0));
}

static void test_the_board_address_is_its_own_origin() {
    TEST_ASSERT_TRUE(latchkey_util::isOwnOrigin("https://192.0.2.63", kBoard));
    TEST_ASSERT_TRUE(latchkey_util::isOwnOrigin("https://192.0.2.63:443", kBoard));
    TEST_ASSERT_TRUE(latchkey_util::isOwnOrigin("HTTPS://192.0.2.63", kBoard));
}

static void test_other_origins_are_not_the_board() {
    const char* refused[] = {
        "http://192.0.2.63", "httpx://192.0.2.63", "https://192.0.2.64", "https://192.0.2.63:8443", "https://192.0.2.63/",
        "https://rebind.attacker.example", "https://owner@192.0.2.63", "null", "", "https://",
    };
    for (const char* origin : refused) {
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::isOwnOrigin(origin, kBoard), origin);
    }
}

static void assertRedirect(const char* host, const char* expected) {
    const std::optional<std::string> target = latchkey_util::httpsRedirect(host);
    TEST_ASSERT_TRUE_MESSAGE(target.has_value(), host);
    TEST_ASSERT_EQUAL_STRING(expected, target->c_str());
}

static void test_the_redirect_points_at_the_https_root() {
    assertRedirect("192.0.2.63", "https://192.0.2.63/");
    assertRedirect("192.0.2.63:80", "https://192.0.2.63/");
    assertRedirect("latchkey-board.example", "https://latchkey-board.example/");
}

static void test_a_malformed_host_gets_no_redirect() {
    const char* refused[] = {
        "", ":80", "attacker.example/path", "a b", "host:abc", "host:", "host:80:80", "[2001:db8::1]", "a\r\nb",
    };
    for (const char* host : refused) {
        TEST_ASSERT_FALSE_MESSAGE(latchkey_util::httpsRedirect(host).has_value(), host);
    }
    TEST_ASSERT_FALSE(latchkey_util::httpsRedirect(std::string(254, 'a')).has_value());
    TEST_ASSERT_TRUE(latchkey_util::httpsRedirect(std::string(253, 'a')).has_value());
}

static void test_the_session_cookie_is_strict_and_the_logout_cookie_clears_it() {
    const std::string token(64, 'f');
    TEST_ASSERT_EQUAL_STRING(("lk_session=" + token + "; Path=/; Secure; HttpOnly; SameSite=Strict").c_str(),
                             latchkey_util::sessionCookie(token).c_str());
    TEST_ASSERT_EQUAL_STRING("lk_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict",
                             latchkey_util::kClearedSessionCookie);
    TEST_ASSERT_EQUAL_STRING("lk_session", latchkey_util::kSessionCookieName);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_json_content_types_are_recognised);
    RUN_TEST(test_other_content_types_are_refused);
    RUN_TEST(test_firmware_uploads_are_octet_streams);
    RUN_TEST(test_the_board_address_is_its_own_host);
    RUN_TEST(test_other_hosts_are_not_the_board);
    RUN_TEST(test_the_board_address_is_its_own_origin);
    RUN_TEST(test_other_origins_are_not_the_board);
    RUN_TEST(test_the_redirect_points_at_the_https_root);
    RUN_TEST(test_a_malformed_host_gets_no_redirect);
    RUN_TEST(test_the_session_cookie_is_strict_and_the_logout_cookie_clears_it);
    return UNITY_END();
}
