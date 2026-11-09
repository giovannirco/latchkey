// SPDX-License-Identifier: GPL-3.0-or-later
#include "http_test_runtime.h"
#define LATCHKEY_NATIVE_REAL_JOBS
#include "rpc_test_runtime.h"
#include "latchkey_util/rpc_text.h"
#include "../../src/ws.cpp"
#include "../../src/jobs.cpp"

namespace http { bool fromBoardAddress(httpd_req_t*) { return true; } }

static esp_err_t admitSocket(int fd, uint32_t session) {
    http_fixture::fd = fd;
    http_fixture::cookie = session == 1 ? "fixture-session" : "fixture-session-2";
    httpd_req_t request;
    const auto admitted = ws::admit(&request);
    if (admitted == ESP_OK) {
        TEST_ASSERT_TRUE(http_fixture::openSocket(fd, {session, false, request.sess_ctx, request.free_ctx}));
    }
    return admitted;
}

void setUp() {
    resetRpcFixture();
    http_fixture::reset();
    ws::init();
    ws::attach(reinterpret_cast<void*>(1), 4);
    TEST_ASSERT_EQUAL(ESP_OK, admitSocket(10, 1));
    TEST_ASSERT_EQUAL(ESP_OK, admitSocket(11, 2));
}

void tearDown() {
    http_fixture::rejectWork = http_fixture::rejectClose = http_fixture::rejectList = false;
    http_fixture::onSend = {};
    http_fixture::onCloseRequested = {};
    while (!http_fixture::work.empty()) http_fixture::runWork();
    ws::service();
    while (!http_fixture::work.empty()) http_fixture::runWork();
    clearRpcFixture();
    TEST_ASSERT_EQUAL_UINT(0, http_fixture::shutdownsOutsideServer);
}

static void deliver(uint32_t session, size_t size = 11000) {
    latchkey_util::RpcText text;
    TEST_ASSERT_TRUE(text.assign(std::string(size, 'x')));
    ws::deliver(session, std::move(text));
}

static void test_targeted_byte_saturation_closes_only_the_affected_session() {
    deliver(1);
    deliver(1);
    deliver(1);
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_TRUE(http_fixture::sockets.at(10).closed);
    TEST_ASSERT_FALSE(http_fixture::sockets.at(11).closed);
}

static void test_active_batch_bytes_remain_reserved_during_new_admission() {
    deliver(1);
    deliver(1);
    bool injected = false;
    http_fixture::onSend = [&] {
        if (injected) return;
        injected = true;
        deliver(2);
    };
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_FALSE(http_fixture::sockets.at(10).closed);
    TEST_ASSERT_TRUE(http_fixture::sockets.at(11).closed);
}

static void test_empty_render_closes_target_after_schedule_and_close_recover() {
    http_fixture::rejectWork = true;
    deliver(1, 0);
    TEST_ASSERT_TRUE(http_fixture::work.empty());
    http_fixture::rejectWork = false;
    http_fixture::rejectClose = true;
    ws::service();
    http_fixture::runWork();
    TEST_ASSERT_FALSE(http_fixture::sockets.at(10).closed);
    http_fixture::rejectClose = false;
    ws::service();
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_TRUE(http_fixture::sockets.at(10).closed);
    TEST_ASSERT_FALSE(http_fixture::sockets.at(11).closed);
}

static void test_oversized_job_result_is_rejected_before_queueing() {
    jobs::Job job{"fixture-job", 1, {}};
    auto line = jobs::doneLine(job, rpc::ok(cJSON_CreateString(std::string(40000, 'x').c_str())));
    TEST_ASSERT_TRUE(line.empty());
}

static void test_job_render_allocation_failure_closes_the_target_session() {
    auto* value = cJSON_CreateString("fixture result");
    auto work = std::make_unique<rpc::JobSpec>();
    work->context = {rpc::Transport::Web, 1};
    work->run = [value](cJSON*, const rpc::Context&) { return rpc::ok(value); };
    failAllocation = allocationAttempts + 1;
    jobs::finish(new jobs::Job{"fixture-job", 1, std::move(work)}, false);
    failAllocation = 0;
    ws::service();
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_TRUE(http_fixture::sockets.at(10).closed);
    TEST_ASSERT_FALSE(http_fixture::sockets.at(11).closed);
    TEST_ASSERT_EQUAL_UINT(0, liveBytes);
}

static void test_all_matching_sockets_close_and_reused_fds_are_not_stale_targets() {
    TEST_ASSERT_EQUAL(ESP_OK, admitSocket(12, 1));
    TEST_ASSERT_EQUAL(ESP_OK, admitSocket(13, 1));
    TEST_ASSERT_EQUAL(ESP_FAIL, admitSocket(14, 2));
    deliver(1, 0);
    while (!http_fixture::work.empty()) http_fixture::runWork();
    for (int fd : {10, 12, 13}) TEST_ASSERT_TRUE(http_fixture::sockets.at(fd).closed);
    TEST_ASSERT_FALSE(http_fixture::sockets.at(11).closed);
    TEST_ASSERT_EQUAL(ESP_OK, admitSocket(10, 2));
    ws::service();
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_FALSE(http_fixture::sockets.at(10).closed);
    TEST_ASSERT_EQUAL(ESP_OK, admitSocket(14, 2));
}

static void test_client_scan_failure_is_retained_until_targeted_close() {
    deliver(1);
    http_fixture::rejectList = true;
    http_fixture::runWork();
    TEST_ASSERT_FALSE(http_fixture::sockets.at(10).closed);
    http_fixture::rejectList = false;
    ws::service();
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_TRUE(http_fixture::sockets.at(10).closed);
    TEST_ASSERT_FALSE(http_fixture::sockets.at(11).closed);
}

static void test_broadcasts_preserve_order_and_targeted_results_remain_private() {
    eventSink("first");
    eventSink("second");
    deliver(1, 12);
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_EQUAL_UINT(5, http_fixture::sent.size());
    TEST_ASSERT_EQUAL_STRING("first", http_fixture::sent[0].second.c_str());
    TEST_ASSERT_EQUAL_STRING("second", http_fixture::sent[1].second.c_str());
    TEST_ASSERT_EQUAL_STRING("first", http_fixture::sent[3].second.c_str());
    TEST_ASSERT_EQUAL_STRING("second", http_fixture::sent[4].second.c_str());
    TEST_ASSERT_FALSE(http_fixture::sockets.at(10).closed);
    TEST_ASSERT_FALSE(http_fixture::sockets.at(11).closed);
}

static void test_message_count_saturation_never_evicts_another_targeted_result() {
    for (size_t i = 0; i < 32; ++i) deliver(1, 12);
    deliver(2, 12);
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_EQUAL_UINT(32, http_fixture::sent.size());
    TEST_ASSERT_FALSE(http_fixture::sockets.at(10).closed);
    TEST_ASSERT_TRUE(http_fixture::sockets.at(11).closed);
}

static void test_session_end_closes_without_sending_and_wipes_queued_payload() {
    auto text = request("fixture private outcome");
    allocation_failure::expectWiped(reinterpret_cast<const uint8_t*>(text.data()), text.capacity() + 1);
    ws::deliver(1, std::move(text));
    endedSession = 1;
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_TRUE(http_fixture::sockets.at(10).closed);
    TEST_ASSERT_FALSE(http_fixture::sockets.at(11).closed);
    TEST_ASSERT_TRUE(http_fixture::sent.empty());
    TEST_ASSERT_EQUAL_UINT(1, allocation_failure::checkedWipes);
    TEST_ASSERT_TRUE(allocation_failure::wiped);
}

static void test_twenty_kib_job_result_fits_the_output_and_queue_budgets() {
    jobs::Job job{"fixture-job", 1, {}};
    auto line = jobs::doneLine(job, rpc::ok(cJSON_CreateString(std::string(20000, 'x').c_str())));
    TEST_ASSERT_GREATER_THAN_UINT(20000, line.size());
    TEST_ASSERT_EQUAL_UINT(32768, line.capacity());
    ws::deliver(1, std::move(line));
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_EQUAL_UINT(1, http_fixture::sent.size());
    TEST_ASSERT_EQUAL_INT(10, http_fixture::sent.front().first);
    TEST_ASSERT_GREATER_THAN_UINT(20000, http_fixture::sent.front().second.size());
    TEST_ASSERT_FALSE(http_fixture::sockets.at(10).closed);
    TEST_ASSERT_FALSE(http_fixture::sockets.at(11).closed);
}

static void test_failed_session_close_cannot_follow_a_reused_session_slot() {
    deliver(1, 0);
    http_fixture::runWork();
    http_fixture::retireSocket(10);
    TEST_ASSERT_EQUAL(ESP_OK, admitSocket(23, 2));
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_FALSE(http_fixture::sockets.at(23).closed);
    TEST_ASSERT_FALSE(http_fixture::sockets.at(11).closed);
    TEST_ASSERT_EQUAL_UINT(1, http_fixture::shutdownCalls);
    TEST_ASSERT_EQUAL_UINT(0, http_fixture::queuedCloses);
}

static void test_duplicate_close_work_cannot_follow_a_reused_descriptor() {
    bool serviced = false;
    http_fixture::onCloseRequested = [&] {
        if (serviced) return;
        serviced = true;
        ws::service();
    };
    deliver(1, 0);
    http_fixture::runWork();
    http_fixture::runWork();
    TEST_ASSERT_TRUE(serviced);
    if (http_fixture::queuedCloses != 0) TEST_ASSERT_EQUAL_UINT(2, http_fixture::queuedCloses);
    http_fixture::retireSocket(10);
    TEST_ASSERT_EQUAL(ESP_OK, admitSocket(10, 2));
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_FALSE(http_fixture::sockets.at(10).closed);
    TEST_ASSERT_FALSE(http_fixture::sockets.at(11).closed);
    TEST_ASSERT_EQUAL_UINT(1, http_fixture::shutdownCalls);
    TEST_ASSERT_EQUAL_UINT(0, http_fixture::queuedCloses);
}

static void test_missing_context_close_cannot_follow_a_reused_session_slot() {
    auto& socket = http_fixture::sockets.at(10);
    socket.freeContext(socket.context);
    socket.context = nullptr;
    socket.freeContext = nullptr;
    ws::service();
    http_fixture::runWork();
    http_fixture::retireSocket(10);
    TEST_ASSERT_EQUAL(ESP_OK, admitSocket(23, 2));
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_FALSE(http_fixture::sockets.at(23).closed);
    TEST_ASSERT_FALSE(http_fixture::sockets.at(11).closed);
    TEST_ASSERT_EQUAL_UINT(1, http_fixture::shutdownCalls);
    TEST_ASSERT_EQUAL_UINT(0, http_fixture::queuedCloses);
}

static void test_missing_context_shutdown_failure_is_retried_on_server_task() {
    auto& socket = http_fixture::sockets.at(10);
    socket.freeContext(socket.context);
    socket.context = nullptr;
    socket.freeContext = nullptr;
    http_fixture::rejectClose = true;
    ws::service();
    http_fixture::runWork();
    TEST_ASSERT_FALSE(socket.closed);
    http_fixture::rejectClose = false;
    ws::service();
    while (!http_fixture::work.empty()) http_fixture::runWork();
    TEST_ASSERT_TRUE(socket.closed);
    TEST_ASSERT_FALSE(http_fixture::sockets.at(11).closed);
    TEST_ASSERT_EQUAL_UINT(2, http_fixture::shutdownCalls);
    TEST_ASSERT_EQUAL_UINT(0, http_fixture::queuedCloses);
}

int main() {
    rpc::init();
    UNITY_BEGIN();
    RUN_TEST(test_targeted_byte_saturation_closes_only_the_affected_session);
    RUN_TEST(test_active_batch_bytes_remain_reserved_during_new_admission);
    RUN_TEST(test_empty_render_closes_target_after_schedule_and_close_recover);
    RUN_TEST(test_oversized_job_result_is_rejected_before_queueing);
    RUN_TEST(test_job_render_allocation_failure_closes_the_target_session);
    RUN_TEST(test_all_matching_sockets_close_and_reused_fds_are_not_stale_targets);
    RUN_TEST(test_client_scan_failure_is_retained_until_targeted_close);
    RUN_TEST(test_broadcasts_preserve_order_and_targeted_results_remain_private);
    RUN_TEST(test_message_count_saturation_never_evicts_another_targeted_result);
    RUN_TEST(test_session_end_closes_without_sending_and_wipes_queued_payload);
    RUN_TEST(test_twenty_kib_job_result_fits_the_output_and_queue_budgets);
    RUN_TEST(test_failed_session_close_cannot_follow_a_reused_session_slot);
    RUN_TEST(test_duplicate_close_work_cannot_follow_a_reused_descriptor);
    RUN_TEST(test_missing_context_close_cannot_follow_a_reused_session_slot);
    RUN_TEST(test_missing_context_shutdown_failure_is_retried_on_server_task);
    return UNITY_END();
}
