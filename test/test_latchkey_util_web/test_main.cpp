// SPDX-License-Identifier: GPL-3.0-or-later
#include <unity.h>

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

static void test_the_own_origin_matches_the_host() {
    TEST_ASSERT_TRUE(latchkey_util::sameOrigin("https://192.0.2.63", "192.0.2.63"));
    TEST_ASSERT_TRUE(latchkey_util::sameOrigin("https://192.0.2.63:443", "192.0.2.63"));
    TEST_ASSERT_TRUE(latchkey_util::sameOrigin("https://192.0.2.63", "192.0.2.63:443"));
    TEST_ASSERT_TRUE(latchkey_util::sameOrigin("HTTPS://192.0.2.63", "192.0.2.63"));
    TEST_ASSERT_TRUE(latchkey_util::sameOrigin("https://Latchkey.Example", "latchkey.example"));
    TEST_ASSERT_TRUE(latchkey_util::sameOrigin("https://192.0.2.63:8443", "192.0.2.63:8443"));
}

static void test_other_origins_do_not_match() {
    TEST_ASSERT_FALSE(latchkey_util::sameOrigin("http://192.0.2.63", "192.0.2.63"));
    TEST_ASSERT_FALSE(latchkey_util::sameOrigin("https://192.0.2.64", "192.0.2.63"));
    TEST_ASSERT_FALSE(latchkey_util::sameOrigin("https://192.0.2.63:8443", "192.0.2.63"));
    TEST_ASSERT_FALSE(latchkey_util::sameOrigin("https://192.0.2.63", "192.0.2.63:8443"));
    TEST_ASSERT_FALSE(latchkey_util::sameOrigin("https://192.0.2.63/", "192.0.2.63"));
    TEST_ASSERT_FALSE(latchkey_util::sameOrigin("https://192.0.2.63.attacker.example", "192.0.2.63"));
    TEST_ASSERT_FALSE(latchkey_util::sameOrigin("https://owner@192.0.2.63", "192.0.2.63"));
    TEST_ASSERT_FALSE(latchkey_util::sameOrigin("null", "192.0.2.63"));
    TEST_ASSERT_FALSE(latchkey_util::sameOrigin("", "192.0.2.63"));
    TEST_ASSERT_FALSE(latchkey_util::sameOrigin("https://", ""));
    TEST_ASSERT_FALSE(latchkey_util::sameOrigin("https://192.0.2.63", ""));
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
    RUN_TEST(test_the_own_origin_matches_the_host);
    RUN_TEST(test_other_origins_do_not_match);
    RUN_TEST(test_the_redirect_points_at_the_https_root);
    RUN_TEST(test_a_malformed_host_gets_no_redirect);
    RUN_TEST(test_the_session_cookie_is_strict_and_the_logout_cookie_clears_it);
    return UNITY_END();
}
