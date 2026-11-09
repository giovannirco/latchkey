// SPDX-License-Identifier: GPL-3.0-or-later
#include "http_test_runtime.h"
#include "rpc_test_runtime.h"
#include "../../src/http.cpp"

const uint8_t kPageStart[] = {0};
const uint8_t kPageEnd[] = {0};
const char kPolicy[] = "fixture";

namespace certs { esp_err_t ensure(uint32_t, latchkey_util::TlsIdentity&) { return ESP_FAIL; } }
namespace wifi { uint32_t address() { return 0xc0000201; } }
namespace ws {
void init() {}
void attach(httpd_handle_t, size_t) {}
esp_err_t admit(httpd_req_t*) { return ESP_OK; }
esp_err_t receive(httpd_req_t*) { return ESP_OK; }
void service() {}
}

void setUp() {
    resetRpcFixture();
    http_fixture::reset();
    TEST_ASSERT_TRUE(http_fixture::openSocket(10, {}));
}
void tearDown() {
    delete static_cast<http::Request*>(http_fixture::request);
    clearRpcFixture();
}

static void largeRequest(httpd_req_t& req, size_t length) {
    http_fixture::body = R"({"method":"fixture.inline","params":{"passphrase":")";
    http_fixture::body.append(length - http_fixture::body.size() - 3, 'x');
    http_fixture::body += "\"}}";
    req.content_len = http_fixture::body.size();
}

static void test_authenticated_maximum_body_is_admitted_and_dispatched() {
    httpd_req_t req;
    largeRequest(req, 16384);
    TEST_ASSERT_EQUAL(ESP_OK, http::acceptRpc(&req));
    TEST_ASSERT_EQUAL_UINT(0, http_fixture::recvCalls);
    auto* pending = static_cast<http::Request*>(http_fixture::request);
    TEST_ASSERT_TRUE(pending->body.empty());
    http_fixture::onReceive = [](char* output, size_t size) {
        allocation_failure::expectWiped(reinterpret_cast<const uint8_t*>(output), size + 1);
    };
    http::answer(*pending);
    TEST_ASSERT_EQUAL_STRING("200 OK", http_fixture::status.c_str());
    TEST_ASSERT_EQUAL_UINT(1, handlerCalls);
    TEST_ASSERT_TRUE(pending->body.empty());
    TEST_ASSERT_TRUE(rawReleasedAtRun);
}

static void test_unauthenticated_body_keeps_the_8192_byte_limit() {
    http_fixture::cookie.clear();
    httpd_req_t req;
    largeRequest(req, 8193);
    TEST_ASSERT_EQUAL(ESP_FAIL, http::acceptRpc(&req));
    TEST_ASSERT_EQUAL_STRING("413 Content Too Large", http_fixture::status.c_str());
    TEST_ASSERT_NULL(http_fixture::request);
    TEST_ASSERT_EQUAL_UINT(0, http_fixture::recvCalls);
}

static void test_revoked_session_is_rechecked_before_receiving_a_large_body() {
    httpd_req_t req;
    largeRequest(req, 16384);
    TEST_ASSERT_EQUAL(ESP_OK, http::acceptRpc(&req));
    openSession = false;
    http::answer(*static_cast<http::Request*>(http_fixture::request));
    TEST_ASSERT_EQUAL_UINT(0, http_fixture::recvCalls);
    TEST_ASSERT_EQUAL_UINT(0, handlerCalls);
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_EQUAL_UINT(1, http_fixture::closed);
}

static void test_authentication_never_permits_more_than_16_kib() {
    httpd_req_t req;
    largeRequest(req, 16385);
    TEST_ASSERT_EQUAL(ESP_FAIL, http::acceptRpc(&req));
    TEST_ASSERT_EQUAL_STRING("413 Content Too Large", http_fixture::status.c_str());
    TEST_ASSERT_EQUAL_UINT(0, http_fixture::recvCalls);
    TEST_ASSERT_NULL(http_fixture::request);
}

static void test_unauthenticated_public_calls_still_accept_8192_bytes() {
    http_fixture::cookie.clear();
    httpd_req_t req;
    largeRequest(req, 8192);
    http_fixture::body.replace(http_fixture::body.find("fixture.inline"), 14, "fixture.public");
    TEST_ASSERT_EQUAL(ESP_OK, http::acceptRpc(&req));
    http::answer(*static_cast<http::Request*>(http_fixture::request));
    TEST_ASSERT_EQUAL_STRING("200 OK", http_fixture::status.c_str());
    TEST_ASSERT_EQUAL_UINT(1, handlerCalls);
}

static void test_body_allocation_failure_closes_without_receiving_or_dispatching() {
    httpd_req_t req;
    largeRequest(req, 16384);
    TEST_ASSERT_EQUAL(ESP_OK, http::acceptRpc(&req));
    allocation_failure::failNext();
    http::answer(*static_cast<http::Request*>(http_fixture::request));
    allocation_failure::resume();
    TEST_ASSERT_EQUAL_UINT(0, http_fixture::recvCalls);
    TEST_ASSERT_EQUAL_UINT(0, handlerCalls);
    TEST_ASSERT_EQUAL_UINT(1, http_fixture::completed);
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_EQUAL_UINT(1, http_fixture::closed);
}

static void test_receive_timeouts_are_bounded_by_the_existing_deadline() {
    httpd_req_t req;
    largeRequest(req, 16384);
    TEST_ASSERT_EQUAL(ESP_OK, http::acceptRpc(&req));
    http_fixture::recvError = HTTPD_SOCK_ERR_TIMEOUT;
    http_fixture::readDelay = 4 * 1000 * 1000;
    http::answer(*static_cast<http::Request*>(http_fixture::request));
    TEST_ASSERT_EQUAL_UINT(3, http_fixture::recvCalls);
    TEST_ASSERT_EQUAL_UINT(0, handlerCalls);
    TEST_ASSERT_EQUAL_UINT(1, http_fixture::completed);
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_EQUAL_UINT(1, http_fixture::closed);
}

static void test_failed_response_render_is_an_explicit_http_failure() {
    httpd_req_t req;
    largeRequest(req, 8192);
    resultSize = 40000;
    TEST_ASSERT_EQUAL(ESP_OK, http::acceptRpc(&req));
    http::answer(*static_cast<http::Request*>(http_fixture::request));
    TEST_ASSERT_EQUAL_STRING("503 Service Unavailable", http_fixture::status.c_str());
    TEST_ASSERT_TRUE(http_fixture::reply.find("reply exceeded memory limits") != std::string::npos);
}

int main() {
    rpc::init();
    rpc::registerMethod("fixture.inline", {}, handle);
    rpc::Access publicAccess;
    publicAccess.needsSession = false;
    rpc::registerMethod("fixture.public", publicAccess, handle);
    UNITY_BEGIN();
    RUN_TEST(test_authenticated_maximum_body_is_admitted_and_dispatched);
    RUN_TEST(test_unauthenticated_body_keeps_the_8192_byte_limit);
    RUN_TEST(test_revoked_session_is_rechecked_before_receiving_a_large_body);
    RUN_TEST(test_authentication_never_permits_more_than_16_kib);
    RUN_TEST(test_unauthenticated_public_calls_still_accept_8192_bytes);
    RUN_TEST(test_body_allocation_failure_closes_without_receiving_or_dispatching);
    RUN_TEST(test_receive_timeouts_are_bounded_by_the_existing_deadline);
    RUN_TEST(test_failed_response_render_is_an_explicit_http_failure);
    return UNITY_END();
}
