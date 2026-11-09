// SPDX-License-Identifier: GPL-3.0-or-later
#include "rpc_test_runtime.h"
#include "latchkey_util/rpc_text.h"
#include "latchkey_util/line_buffer.h"

void setUp() { resetRpcFixture(); }
void tearDown() { clearRpcFixture(); }

static void test_decoded_nul_is_rejected_before_the_handler() {
    const auto response = dispatchRequest(
        request(R"({"id":1,"method":"fixture.inline","params":{"passphrase":"private\u0000tail"}})"),
        rpc::Transport::Serial, {});
    TEST_ASSERT_TRUE(hasError(response, "bad_request"));
    TEST_ASSERT_EQUAL_UINT(0, handlerCalls);
}

static void test_parsed_secrets_are_erased_when_the_request_is_rejected() {
    watchedSecret = "fixture sensitive passphrase";
    const auto response = dispatchRequest(
        request(R"({"id":1,"method":"missing","params":{"passphrase":"fixture sensitive passphrase"}})"),
        rpc::Transport::Serial, {});
    TEST_ASSERT_TRUE(hasError(response, "unknown_method"));
    TEST_ASSERT_EQUAL_UINT(0, unclearedSecrets);
}

static void test_partial_parser_failure_erases_already_decoded_secrets() {
    watchedSecret = "fixture sensitive passphrase";
    const auto response = dispatchRequest(
        request(R"({"id":1,"params":{"passphrase":"fixture sensitive passphrase"},"broken":])"),
        rpc::Transport::Serial, {});
    TEST_ASSERT_TRUE(hasError(response, "bad_request"));
    TEST_ASSERT_EQUAL_UINT(0, unclearedSecrets);
}

static void test_raw_request_is_released_before_an_immediately_started_job() {
    runImmediately = true;
    auto input = request(R"({"id":"owned-id","method":"fixture.job","params":{"passphrase":"fixture secret"}})");
    allocation_failure::expectWiped(reinterpret_cast<const uint8_t*>(input.data()), input.capacity() + 1);
    const auto response = dispatchRequest(std::move(input), rpc::Transport::Web, "fixture-session");
    TEST_ASSERT_EQUAL_UINT(1, handlerCalls);
    TEST_ASSERT_TRUE(rawReleasedAtRun);
    TEST_ASSERT_TRUE(paramsNotDuplicated);
    TEST_ASSERT_TRUE(std::string_view(response.json.c_str()).find("owned-id") != std::string_view::npos);
}

static void test_literal_nul_is_rejected_in_a_length_delimited_request() {
    std::string text = R"({"method":"fixture.inline"})";
    text.push_back('\0');
    text += "ignored";
    const auto response = dispatchRequest(request(text), rpc::Transport::Serial, {});
    TEST_ASSERT_TRUE(hasError(response, "bad_request"));
    TEST_ASSERT_EQUAL_UINT(0, handlerCalls);
}

static void test_escaped_backslash_and_other_utf8_controls_remain_supported() {
    const auto response = dispatchRequest(request(
        R"({"method":"fixture.inline","params":{"passphrase":"literal\\u0000\n\t\r\u007f"}})"),
        rpc::Transport::Serial, {});
    TEST_ASSERT_EQUAL_UINT(1, handlerCalls);
    TEST_ASSERT_FALSE(hasError(response, "bad_request"));
}

static void test_delayed_jobs_release_secret_parameters_on_every_outcome() {
    watchedSecret = "fixture sensitive passphrase";
    for (unsigned outcome = 0; outcome < 6; ++outcome) {
        openSession = pressAllowed = true;
        invalidArguments = handlerFails = rejectJob = false;
        if (outcome == 0) rejectJob = true;
        {
            auto response = dispatchRequest(request(
                R"({"id":42,"method":"fixture.job","params":{"passphrase":"fixture sensitive passphrase"}})"),
                rpc::Transport::Web, "fixture-session");
            if (outcome == 0) {
                TEST_ASSERT_TRUE(hasError(response, "busy"));
                TEST_ASSERT_FALSE(queuedWork.has_value());
            } else {
                TEST_ASSERT_TRUE(queuedWork.has_value());
                openSession = outcome != 1;
                pressAllowed = outcome != 3;
                invalidArguments = outcome == 4;
                handlerFails = outcome == 5;
                auto reply = rpc::executeJob(std::move(**queuedWork), outcome == 2);
                queuedWork.reset();
                TEST_ASSERT_FALSE(reply.error.empty());
            }
        }
        TEST_ASSERT_EQUAL_UINT(0, liveBytes);
        TEST_ASSERT_EQUAL_UINT(0, unclearedSecrets);
    }
    TEST_ASSERT_EQUAL_UINT(2, confirmations);
    TEST_ASSERT_EQUAL_UINT(1, handlerCalls);
}

static void test_large_render_is_bounded_and_releases_its_json_tree() {
    resultSize = 40000;
    const auto response = dispatchRequest(request(R"({"method":"fixture.inline"})"), rpc::Transport::Serial, {});
    TEST_ASSERT_TRUE(response.json.empty());
    TEST_ASSERT_EQUAL_UINT(0, liveBytes);
}

static void test_each_parser_and_render_allocation_failure_releases_every_owned_allocation() {
    watchedSecret = "fixture sensitive passphrase";
    for (size_t failure = 1; failure <= 40; ++failure) {
        allocationAttempts = 0;
        failAllocation = failure;
        {
            auto response = dispatchRequest(request(
                R"({"id":"fixture-id","method":"missing","params":{"passphrase":"fixture sensitive passphrase"}})"),
                rpc::Transport::Serial, {});
            failAllocation = 0;
        }
        TEST_ASSERT_EQUAL_UINT(0, liveBytes);
        TEST_ASSERT_EQUAL_UINT(0, unclearedSecrets);
    }
}

static void test_large_ids_have_one_owned_json_representation_during_rendering() {
    std::string input = R"({"method":"fixture.inline","id":")";
    input.append(16000, 'x');
    input += "\"}";
    bool rendered = false;
    {
        const auto response = dispatchRequest(request(input), rpc::Transport::Serial, {});
        rendered = !response.json.empty();
    }
    TEST_ASSERT_TRUE(rendered);
    TEST_ASSERT_LESS_OR_EQUAL_UINT(34 * 1024, peakTransportBytes);
    TEST_ASSERT_EQUAL_UINT(0, liveBytes);
}

static void test_job_acknowledgement_allocation_failure_prevents_submission() {
    rpc::JobSpec spec;
    spec.context = {rpc::Transport::Web, 1};
    spec.run = handle;
    failAllocation = allocationAttempts + 1;
    auto reply = rpc::startJob(std::move(spec));
    failAllocation = 0;
    TEST_ASSERT_EQUAL_STRING("internal", reply.error.c_str());
    TEST_ASSERT_FALSE(queuedWork.has_value());
}

static void test_maximum_request_transfers_one_parameter_copy_within_34_kib() {
    watchedSecret = "fixture secret prefix";
    std::string input = R"({"method":"fixture.job","params":{"passphrase":"fixture secret prefix)";
    input.append(16384 - input.size() - 3, 'x');
    input += "\"}}";
    const auto response = dispatchRequest(request(input), rpc::Transport::Web, "fixture-session");
    TEST_ASSERT_TRUE(queuedWork.has_value());
    TEST_ASSERT_EQUAL_UINT(1, parameterCopiesAtSubmit);
    TEST_ASSERT_LESS_OR_EQUAL_UINT(34 * 1024, peakTransportBytes);
    auto reply = rpc::executeJob(std::move(**queuedWork), false);
    queuedWork.reset();
    TEST_ASSERT_TRUE(reply.error.empty());
    TEST_ASSERT_EQUAL_UINT(0, liveBytes);
}

static void test_backup_sized_result_uses_one_output_buffer_within_28_kib() {
    resultSize = 11000;
    size_t rendered = 0;
    {
        const auto response = dispatchRequest(request(R"({"method":"fixture.inline"})"), rpc::Transport::Serial, {});
        rendered = response.json.size();
    }
    TEST_ASSERT_GREATER_THAN_UINT(11000, rendered);
    TEST_ASSERT_LESS_OR_EQUAL_UINT(28 * 1024, peakTransportBytes);
    TEST_ASSERT_EQUAL_UINT(0, liveBytes);
}

static void test_maximum_body_and_value_count_stay_within_54_kib() {
    std::string input = R"({"method":"fixture.inline","params":{"values":[")";
    input.append(16384 - input.size() - 1245, 'x');
    input += '"';
    for (size_t i = 0; i < 248; ++i) input += ",null";
    input += "]}}";
    TEST_ASSERT_LESS_OR_EQUAL_UINT(16384, input.size());
    const auto response = dispatchRequest(request(input), rpc::Transport::Serial, {});
    TEST_ASSERT_EQUAL_UINT(1, handlerCalls);
    TEST_ASSERT_LESS_OR_EQUAL_UINT(54 * 1024, peakTransportBytes);
    TEST_ASSERT_EQUAL_UINT(0, liveBytes);
}

static void test_render_buffer_allocation_failures_release_the_json_result() {
    for (size_t failure = 1; failure <= 7; ++failure) {
        rpc::Json value(cJSON_CreateString(std::string(11000, 'x').c_str()));
        allocation_failure::attempts = 0;
        allocation_failure::failAt = failure;
        auto output = rpc::render(std::move(value));
        allocation_failure::resume();
        TEST_ASSERT_TRUE(output.empty());
        TEST_ASSERT_EQUAL_UINT(0, liveBytes);
    }
}

static void test_json_allocator_preserves_alignment_and_borrowed_strings() {
    void* allocation = cJSON_malloc(1);
    TEST_ASSERT_NOT_NULL(allocation);
    TEST_ASSERT_EQUAL_UINT(0, reinterpret_cast<uintptr_t>(allocation) % alignof(std::max_align_t));
    cJSON_free(allocation);
    TEST_ASSERT_NULL(cJSON_malloc(SIZE_MAX));
    cJSON_free(nullptr);
    char borrowed[] = "borrowed fixture";
    rpc::Json value(cJSON_CreateStringReference(borrowed));
    rpc::Json object(cJSON_CreateObject());
    TEST_ASSERT_TRUE(cJSON_AddItemToObjectCS(object.get(), "constant-key", value.get()));
    value.release();
    object.reset();
    TEST_ASSERT_EQUAL_STRING("borrowed fixture", borrowed);
    TEST_ASSERT_EQUAL_UINT(0, liveBytes);
}

static void test_serial_maximum_request_runs_inline_after_both_raw_copies_are_erased() {
    std::string input = R"({"method":"fixture.job","params":{"passphrase":")";
    input.append(16384 - input.size() - 3, 'x');
    input += "\"}}\n";
    char chunk[256]{};
    latchkey_util::RpcText response;
    latchkey_util::LineBuffer lines(16384, [&](latchkey_util::RpcText line) {
        for (char byte : chunk) TEST_ASSERT_EQUAL_INT(0, byte);
        allocation_failure::expectWiped(reinterpret_cast<const uint8_t*>(line.data()), line.capacity() + 1);
        response = rpc::dispatch(std::move(line), rpc::Transport::Serial, {}).json;
    }, [](auto) { TEST_FAIL_MESSAGE("maximum serial request was rejected"); });
    for (size_t offset = 0; offset < input.size(); offset += sizeof(chunk)) {
        const size_t count = std::min(sizeof(chunk), input.size() - offset);
        std::memcpy(chunk, input.data() + offset, count);
        lines.consume(chunk, count);
    }
    TEST_ASSERT_EQUAL_UINT(1, handlerCalls);
    TEST_ASSERT_EQUAL_UINT(0, confirmations);
    TEST_ASSERT_FALSE(queuedWork.has_value());
    TEST_ASSERT_TRUE(rawReleasedAtRun);
    TEST_ASSERT_FALSE(response.empty());
}

static void test_existing_large_list_responses_exceed_the_request_limit() {
    resultSize = 20000;
    const auto response = dispatchRequest(request(R"({"method":"fixture.inline"})"), rpc::Transport::Serial, {});
    TEST_ASSERT_GREATER_THAN_UINT(20000, response.json.size());
}

int main() {
    rpc::init();
    rpc::registerMethod("fixture.inline", {}, handle);
    rpc::Access job;
    job.job = true;
    job.needsButton = true;
    rpc::registerMethod("fixture.job", job, handle, check);
    UNITY_BEGIN();
    RUN_TEST(test_decoded_nul_is_rejected_before_the_handler);
    RUN_TEST(test_parsed_secrets_are_erased_when_the_request_is_rejected);
    RUN_TEST(test_partial_parser_failure_erases_already_decoded_secrets);
    RUN_TEST(test_raw_request_is_released_before_an_immediately_started_job);
    RUN_TEST(test_literal_nul_is_rejected_in_a_length_delimited_request);
    RUN_TEST(test_escaped_backslash_and_other_utf8_controls_remain_supported);
    RUN_TEST(test_delayed_jobs_release_secret_parameters_on_every_outcome);
    RUN_TEST(test_large_render_is_bounded_and_releases_its_json_tree);
    RUN_TEST(test_each_parser_and_render_allocation_failure_releases_every_owned_allocation);
    RUN_TEST(test_large_ids_have_one_owned_json_representation_during_rendering);
    RUN_TEST(test_job_acknowledgement_allocation_failure_prevents_submission);
    RUN_TEST(test_maximum_request_transfers_one_parameter_copy_within_34_kib);
    RUN_TEST(test_backup_sized_result_uses_one_output_buffer_within_28_kib);
    RUN_TEST(test_maximum_body_and_value_count_stay_within_54_kib);
    RUN_TEST(test_render_buffer_allocation_failures_release_the_json_result);
    RUN_TEST(test_json_allocator_preserves_alignment_and_borrowed_strings);
    RUN_TEST(test_serial_maximum_request_runs_inline_after_both_raw_copies_are_erased);
    RUN_TEST(test_existing_large_list_responses_exceed_the_request_limit);
    return UNITY_END();
}
