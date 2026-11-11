// SPDX-License-Identifier: GPL-3.0-or-later
#include "http_test_runtime.h"
#include "rpc_test_runtime.h"
#include "esp_tls_errors.h"

namespace body_fixture {
int flags = 0;
bool rejectFlags = false;
size_t flagCalls = 0, rejectFlagCall = 0;
std::vector<int64_t> waits;
std::vector<bool> writeWaits;
std::function<int()> onSelect;

int setFlags(int, int command, int value = 0) {
    if (rejectFlags || ++flagCalls == rejectFlagCall) return -1;
    if (command == F_GETFL) return flags;
    flags = value;
    return 0;
}

int waitForSocket(int, fd_set* readable, fd_set* writable, fd_set*, timeval* timeout) {
    TEST_ASSERT_TRUE((readable == nullptr) != (writable == nullptr));
    const int64_t remaining = timeout->tv_sec * 1000000 + timeout->tv_usec;
    waits.push_back(remaining);
    writeWaits.push_back(writable != nullptr);
    if (onSelect) return onSelect();
    http_fixture::now += remaining;
    return 0;
}
}

#define fcntl body_fixture::setFlags
#define select body_fixture::waitForSocket
#include "../../src/http.cpp"
#undef select
#undef fcntl

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
    body_fixture::flags = 0;
    body_fixture::rejectFlags = false;
    body_fixture::flagCalls = body_fixture::rejectFlagCall = 0;
    body_fixture::waits.clear();
    body_fixture::writeWaits.clear();
    body_fixture::onSelect = {};
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
    http_fixture::onReceive = [](char*, size_t) {
        http_fixture::readDelay = body_fixture::flags & O_NONBLOCK ? 0 : 4000000;
    };
    http::answer(*static_cast<http::Request*>(http_fixture::request));
    TEST_ASSERT_EQUAL_INT64(10 * 1000 * 1000, http_fixture::now);
    TEST_ASSERT_EQUAL_UINT(1, http_fixture::recvCalls);
    TEST_ASSERT_EQUAL_UINT(0, handlerCalls);
    TEST_ASSERT_EQUAL_UINT(1, http_fixture::completed);
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_EQUAL_UINT(1, http_fixture::closed);
}

static void test_failed_body_shuts_down_before_releasing_async_socket_ownership() {
    httpd_req_t req;
    largeRequest(req, 8192);
    TEST_ASSERT_EQUAL(ESP_OK, http::acceptRpc(&req));
    http_fixture::recvError = -1;
    bool shutdownWhileOwned = false;
    http_fixture::onCloseRequested = [&] {
        shutdownWhileOwned = http_fixture::sockets.at(10).asynchronous;
    };
    http_fixture::onComplete = [] {
        http_fixture::retireSocket(10);
        TEST_ASSERT_TRUE(http_fixture::openSocket(10, {}));
    };
    http::answer(*static_cast<http::Request*>(http_fixture::request));
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_TRUE(shutdownWhileOwned);
    TEST_ASSERT_FALSE(http_fixture::sockets.at(10).closed);
    TEST_ASSERT_EQUAL_UINT(0, http_fixture::queuedCloses);
}

static void test_anonymous_slow_body_releases_the_worker_within_two_seconds() {
    http_fixture::cookie.clear();
    httpd_req_t req;
    largeRequest(req, 8192);
    TEST_ASSERT_EQUAL(ESP_OK, http::acceptRpc(&req));
    http_fixture::recvError = ESP_TLS_ERR_SSL_WANT_READ;
    http::answer(*static_cast<http::Request*>(http_fixture::request));
    TEST_ASSERT_EQUAL_INT64(2 * 1000 * 1000, http_fixture::now);
    TEST_ASSERT_EQUAL_UINT(0, handlerCalls);
    TEST_ASSERT_EQUAL_UINT(1, http_fixture::completed);
    TEST_ASSERT_TRUE(http_fixture::sockets.at(10).closed);
    TEST_ASSERT_EQUAL_INT(0, body_fixture::flags);
}

static void test_tls_partial_reads_use_one_deadline_and_restore_blocking_mode() {
    httpd_req_t req;
    largeRequest(req, 16384);
    TEST_ASSERT_EQUAL(ESP_OK, http::acceptRpc(&req));
    http_fixture::recvError = ESP_TLS_ERR_SSL_WANT_READ;
    body_fixture::onSelect = [] {
        http_fixture::now += 1000000;
        http_fixture::recvError = body_fixture::waits.size() == 1 ? ESP_TLS_ERR_SSL_WANT_WRITE : 0;
        return 1;
    };
    http_fixture::onReceive = [](char*, size_t) {
        TEST_ASSERT_NOT_EQUAL(0, body_fixture::flags & O_NONBLOCK);
    };
    http::answer(*static_cast<http::Request*>(http_fixture::request));
    TEST_ASSERT_EQUAL_UINT(1, handlerCalls);
    TEST_ASSERT_EQUAL_UINT(2, body_fixture::waits.size());
    TEST_ASSERT_EQUAL_INT64(10000000, body_fixture::waits[0]);
    TEST_ASSERT_EQUAL_INT64(9000000, body_fixture::waits[1]);
    TEST_ASSERT_FALSE(body_fixture::writeWaits[0]);
    TEST_ASSERT_TRUE(body_fixture::writeWaits[1]);
    TEST_ASSERT_EQUAL_INT(0, body_fixture::flags);
}

static void test_socket_mode_failure_closes_without_reading_or_dispatching() {
    httpd_req_t req;
    largeRequest(req, 8192);
    TEST_ASSERT_EQUAL(ESP_OK, http::acceptRpc(&req));
    body_fixture::rejectFlags = true;
    http::answer(*static_cast<http::Request*>(http_fixture::request));
    TEST_ASSERT_EQUAL_UINT(0, http_fixture::recvCalls);
    TEST_ASSERT_EQUAL_UINT(0, handlerCalls);
    TEST_ASSERT_TRUE(http_fixture::sockets.at(10).closed);
}

static void test_https_stack_is_unknown_until_task_observed_but_preserves_zero() {
    http::s_server = nullptr;
    const std::optional<uint32_t> unknown = http::serverStackFree();
    TEST_ASSERT_FALSE(unknown.has_value());
    http::noteServerTask();
    const std::optional<uint32_t> exhausted = http::serverStackFree();
    TEST_ASSERT_TRUE(exhausted.has_value());
    TEST_ASSERT_EQUAL_UINT32(0, *exhausted);
}

static void test_interrupted_wait_recomputes_the_remaining_deadline() {
    http_fixture::cookie.clear();
    httpd_req_t req;
    largeRequest(req, 8192);
    TEST_ASSERT_EQUAL(ESP_OK, http::acceptRpc(&req));
    http_fixture::recvError = ESP_TLS_ERR_SSL_WANT_READ;
    body_fixture::onSelect = [] {
        http_fixture::now += 1000000;
        errno = EINTR;
        return -1;
    };
    http::answer(*static_cast<http::Request*>(http_fixture::request));
    TEST_ASSERT_EQUAL_UINT(2, body_fixture::waits.size());
    TEST_ASSERT_EQUAL_INT64(2000000, body_fixture::waits[0]);
    TEST_ASSERT_EQUAL_INT64(1000000, body_fixture::waits[1]);
    TEST_ASSERT_EQUAL_INT64(2000000, http_fixture::now);
    TEST_ASSERT_EQUAL_UINT(0, handlerCalls);
    TEST_ASSERT_EQUAL_INT(0, body_fixture::flags);
}

static void test_select_failure_restores_original_socket_mode_and_wipes_body() {
    httpd_req_t req;
    largeRequest(req, 8192);
    TEST_ASSERT_EQUAL(ESP_OK, http::acceptRpc(&req));
    body_fixture::flags = O_APPEND;
    http_fixture::recvError = ESP_TLS_ERR_SSL_WANT_READ;
    http_fixture::onReceive = [](char* output, size_t size) {
        allocation_failure::expectWiped(reinterpret_cast<const uint8_t*>(output), size + 1);
    };
    body_fixture::onSelect = [] { errno = EIO; return -1; };
    http::answer(*static_cast<http::Request*>(http_fixture::request));
    TEST_ASSERT_EQUAL_INT(O_APPEND, body_fixture::flags);
    TEST_ASSERT_EQUAL_UINT(0, handlerCalls);
    TEST_ASSERT_EQUAL_UINT(1, allocation_failure::checkedWipes);
    TEST_ASSERT_TRUE(allocation_failure::wiped);
    TEST_ASSERT_TRUE(http_fixture::sockets.at(10).closed);
}

static void test_cannot_restore_blocking_mode_closes_before_dispatching() {
    httpd_req_t req;
    largeRequest(req, 8192);
    TEST_ASSERT_EQUAL(ESP_OK, http::acceptRpc(&req));
    body_fixture::rejectFlagCall = 3;
    http::answer(*static_cast<http::Request*>(http_fixture::request));
    TEST_ASSERT_EQUAL_UINT(1, http_fixture::recvCalls);
    TEST_ASSERT_EQUAL_UINT(0, handlerCalls);
    TEST_ASSERT_TRUE(http_fixture::sockets.at(10).closed);
}

static void test_partial_progress_does_not_extend_the_anonymous_deadline() {
    http_fixture::cookie.clear();
    httpd_req_t req;
    largeRequest(req, 8192);
    TEST_ASSERT_EQUAL(ESP_OK, http::acceptRpc(&req));
    http_fixture::readChunk = 1;
    http_fixture::readDelay = 100000;
    http::answer(*static_cast<http::Request*>(http_fixture::request));
    TEST_ASSERT_EQUAL_INT64(2000000, http_fixture::now);
    TEST_ASSERT_EQUAL_UINT(20, http_fixture::recvCalls);
    TEST_ASSERT_EQUAL_UINT(0, handlerCalls);
    TEST_ASSERT_TRUE(http_fixture::sockets.at(10).closed);
    TEST_ASSERT_EQUAL_INT(0, body_fixture::flags);
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
    RUN_TEST(test_failed_body_shuts_down_before_releasing_async_socket_ownership);
    RUN_TEST(test_anonymous_slow_body_releases_the_worker_within_two_seconds);
    RUN_TEST(test_tls_partial_reads_use_one_deadline_and_restore_blocking_mode);
    RUN_TEST(test_socket_mode_failure_closes_without_reading_or_dispatching);
    RUN_TEST(test_https_stack_is_unknown_until_task_observed_but_preserves_zero);
    RUN_TEST(test_interrupted_wait_recomputes_the_remaining_deadline);
    RUN_TEST(test_select_failure_restores_original_socket_mode_and_wipes_body);
    RUN_TEST(test_cannot_restore_blocking_mode_closes_before_dispatching);
    RUN_TEST(test_partial_progress_does_not_extend_the_anonymous_deadline);
    RUN_TEST(test_failed_response_render_is_an_explicit_http_failure);
    return UNITY_END();
}
