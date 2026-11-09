// SPDX-License-Identifier: GPL-3.0-or-later
#include <algorithm>
#include <array>
#include <cstdio>
#include <string>
#include <vector>

#include "esp_random.h"
#include "mbedtls/platform_util.h"

#include "access_requests.h"
#include "clock.h"
#include "hmac.h"
#include "latchkey_util/harden_plan.h"
#include "latchkey_util/passcode_id.h"
#include "lock_manager.h"
#include "methods.h"
#include "rpc.h"

namespace methods {
namespace {

using latchkey_util::HardenAdmin;
using latchkey_util::HardenPlan;
using latchkey_util::HardenPreservation;
using ttlock::Status;

struct HardenRequest {
    std::string mac;
    bool dryRun = false;
};

rpc::Reply readHarden(const cJSON* params, HardenRequest& request) {
    const auto* dryRun = lock_access::member(params, "dryRun");
    if (dryRun != nullptr && !cJSON_IsBool(dryRun)) return rpc::fail("invalid_argument", "dryRun must be true or false");
    request.dryRun = cJSON_IsTrue(dryRun);
    if (!lock_access::readLock(params, request.mac)) return rpc::fail("invalid_argument", lock_access::kLockMessage);
    if (!lock_manager::holds(request.mac)) return rpc::fail("not_paired", "the board has no keys for this lock");
    lock_manager::AdminState state;
    if (lock_manager::readAdminState(request.mac, state) != ESP_OK) {
        return rpc::fail("storage_error", "cannot read the lock recovery state");
    }
    latchkey_util::LabelTable labels;
    if (lock_manager::loadLabels(request.mac, store::labels::Kind::Passcodes, labels) != ESP_OK) {
        return rpc::fail("storage_error", "cannot read managed passcode labels");
    }
    if (!request.dryRun && (state.metadata.lifecycle & latchkey_util::kBackupBackedUp) == 0) {
        return rpc::fail("backup_required", "export a backup of this pairing before hardening");
    }
    if (!request.dryRun && !wallclock::synced()) return rpc::fail("time_unsynced", "set the board clock before hardening");
    return rpc::ok();
}

rpc::Reply checkHarden(const cJSON* params, const rpc::Context&) {
    HardenRequest request;
    auto reply = readHarden(params, request);
    reply.target = request.mac;
    reply.audited = !request.dryRun;
    return reply;
}

struct HardenEvidence {
    lock_manager::AdminState state;
    latchkey_util::LabelTable labels;
    std::string current;
    std::vector<ttlock::Passcode> passcodes;
    std::vector<latchkey_util::HardenPasscode> codes;
    ~HardenEvidence() {
        lock_access::wipe(current);
        for (auto& code : passcodes) lock_access::wipe(code.code);
    }
};

Status readHardenEvidence(ttlock::Session& session, const HardenRequest& request, HardenEvidence& evidence,
                          rpc::Reply& out) {
    if (lock_manager::readAdminState(request.mac, evidence.state) != ESP_OK ||
        lock_manager::loadLabels(request.mac, store::labels::Kind::Passcodes, evidence.labels) != ESP_OK) {
        out = rpc::fail("storage_error", "cannot read the lock recovery state and managed labels");
        return Status::Ok;
    }
    if (!request.dryRun && (evidence.state.metadata.lifecycle & latchkey_util::kBackupBackedUp) == 0) {
        out = rpc::fail("backup_required", "export a backup of this pairing before hardening");
        return Status::Ok;
    }
    if (evidence.state.record.features == 0) {
        uint64_t features = 0;
        const auto read = session.features(features);
        if (read != Status::Ok) return read;
    }
    const auto admin = session.adminPasscodeGet(evidence.current);
    if (admin != Status::Ok && admin != Status::Unsupported) return admin;
    const auto listed = session.passcodeList(evidence.passcodes);
    if (listed != Status::Ok) return listed;
    if (!lock_access::listFits(evidence.passcodes.size() * 160 + 2048)) {
        out = lock_access::tooLarge(evidence.passcodes.size(), "passcodes");
        return Status::Ok;
    }
    ttlock::AesKey key{};
    std::copy(std::begin(evidence.state.record.aesKey), std::end(evidence.state.record.aesKey), key.begin());
    bool identified = true;
    for (const auto& code : evidence.passcodes) {
        latchkey_util::PasscodeId id{};
        if (!latchkey_util::passcodeId(key, code.code, hmac::sha256, id)) { identified = false; break; }
        evidence.codes.push_back({latchkey_util::passcodeIdNumber(id), code.code, code.type});
    }
    mbedtls_platform_zeroize(key.data(), key.size());
    if (!identified) out = rpc::fail("internal", "cannot identify passcodes");
    return Status::Ok;
}

const char* adminReason(HardenAdmin admin) {
    switch (admin) {
        case HardenAdmin::PreserveUnknown: return "legacy_unknown";
        case HardenAdmin::PreserveOwner: return "owner";
        case HardenAdmin::PreserveHardened: return "hardening_generated";
        case HardenAdmin::Rotate: return "pairing_generated";
        case HardenAdmin::ConfirmCandidate: return "confirm_candidate";
        case HardenAdmin::ConfirmPrevious: return "confirm_previous";
        case HardenAdmin::Unresolved: return "admin_unresolved";
    }
    return "admin_unresolved";
}

const char* preservationReason(HardenPreservation reason) {
    switch (reason) {
        case HardenPreservation::Unmanaged: return "unmanaged";
        case HardenPreservation::Managed: return "managed";
        case HardenPreservation::Admin: return "admin";
        case HardenPreservation::Unknown: return "unknown";
    }
    return "unknown";
}

bool preservesAdmin(HardenAdmin admin) {
    return admin == HardenAdmin::PreserveUnknown || admin == HardenAdmin::PreserveOwner ||
           admin == HardenAdmin::PreserveHardened;
}

struct HardenResult {
    const HardenPlan& plan;
    std::array<const char*, 4> steps{"planned", "planned", "planned", "skipped"};
    std::array<std::string, 4> errors;
    std::vector<const char*> codes;
    const char* completion = "preview";
    size_t removed = 0;
    explicit HardenResult(const HardenPlan& value) : plan(value) {
        if (preservesAdmin(plan.admin)) steps[2] = "preserved";
        if (plan.admin == HardenAdmin::Unresolved) steps[2] = "skipped";
        for (const auto& code : plan.passcodes) codes.push_back(code.remove ? "planned" : "preserved");
    }
    void fail(size_t step, const std::string& error) {
        steps[step] = "failed";
        errors[step] = error;
        completion = "failed";
    }
    bool addPasscodes(cJSON* step) const {
        if (!cJSON_AddNumberToObject(step, "removed", removed)) return false;
        cJSON* entries = cJSON_AddArrayToObject(step, "entries");
        if (!entries) return false;
        size_t planned = 0;
        for (size_t j = 0; j < plan.passcodes.size(); ++j) {
            const auto& code = plan.passcodes[j];
            planned += code.remove;
            rpc::Json entry(cJSON_CreateObject());
            char id[13];
            std::snprintf(id, sizeof(id), "%012llx", static_cast<unsigned long long>(code.id));
            if (!entry || !cJSON_AddStringToObject(entry.get(), "id", id) ||
                !cJSON_AddStringToObject(entry.get(), "status", codes[j]) ||
                !cJSON_AddStringToObject(entry.get(), "reason", preservationReason(code.reason)) ||
                !cJSON_AddItemToArray(entries, entry.get())) return false;
            entry.release();
        }
        return cJSON_AddNumberToObject(step, "planned", planned) &&
               cJSON_AddNumberToObject(step, "preserved", plan.passcodes.size() - planned);
    }
    rpc::Json json(bool dryRun) const {
        rpc::Json result(cJSON_CreateObject());
        if (!result || !cJSON_AddBoolToObject(result.get(), "dryRun", dryRun) ||
            !cJSON_AddBoolToObject(result.get(), "hardened", false) ||
            !cJSON_AddBoolToObject(result.get(), "executable", plan.executable) ||
            !cJSON_AddStringToObject(result.get(), "completion", completion)) return {};
        cJSON* items = cJSON_AddArrayToObject(result.get(), "steps");
        if (!items) return {};
        constexpr const char* names[]{"time", "passcodes", "admin", "resetButton"};
        for (size_t i = 0; i < steps.size(); ++i) {
            rpc::Json step(cJSON_CreateObject());
            if (!step || !cJSON_AddStringToObject(step.get(), "step", names[i]) ||
                !cJSON_AddStringToObject(step.get(), "status", steps[i])) return {};
            if (!errors[i].empty() && !cJSON_AddStringToObject(step.get(), "error", errors[i].c_str())) return {};
            if (i == 2 && !cJSON_AddStringToObject(step.get(), "reason", adminReason(plan.admin))) return {};
            if (i == 3 && !cJSON_AddStringToObject(step.get(), "reason", "unverified_switch_layout")) return {};
            if (i == 1 && !addPasscodes(step.get())) return {};
            if (!cJSON_AddItemToArray(items, step.get())) return {};
            step.release();
        }
        return result;
    }
};

lock_access::Secret hardeningCandidate(const HardenEvidence& evidence) {
    for (size_t attempt = 0; attempt < 32; ++attempt) {
        std::string value(ttlock::kAdminPasscodeDigits, '0');
        for (char& digit : value) {
            uint32_t random = esp_random();
            while (random >= 4294967290u) random = esp_random();
            digit = static_cast<char>('0' + random % 10);
        }
        const lock_access::Secret candidate(value);
        lock_access::wipe(value);
        const bool collision = candidate.get() == evidence.current || candidate.get() == evidence.state.record.adminPasscode ||
            std::any_of(evidence.passcodes.begin(), evidence.passcodes.end(), [&](const auto& code) { return code.code == candidate.get(); });
        if (!collision) return candidate;
    }
    return {};
}

rpc::Reply changeHardeningAdmin(ttlock::Session& session, const HardenRequest& request,
                               const HardenEvidence& evidence, HardenAdmin action) {
    if (action == HardenAdmin::ConfirmCandidate || action == HardenAdmin::ConfirmPrevious) {
        return lock_manager::reconcileAdminPasscode(request.mac, evidence.current) == ESP_OK
                   ? rpc::ok() : rpc::fail("admin_unresolved", "cannot store the authenticated admin verdict");
    }
    const auto candidate = hardeningCandidate(evidence);
    if (candidate.empty()) return rpc::fail("code_collision", "cannot generate an unused admin code");
    if (lock_manager::stageAdminPasscode(request.mac, candidate.get(), latchkey_util::AdminProvenance::HardeningGenerated) != ESP_OK) {
        return rpc::fail("storage_error", "cannot store the pending admin change");
    }
    const auto status = session.setAdminPasscode(candidate.get());
    if (status == Status::LockError && lock_manager::rejectAdminPasscode(request.mac) != ESP_OK) {
        return rpc::fail("admin_unresolved", "cannot clear the refused admin change");
    }
    if (status != Status::Ok) return lock_manager::failure(status, session.lockErrorCode());
    return lock_manager::confirmAdminPasscode(request.mac) == ESP_OK
               ? rpc::ok() : rpc::fail("admin_unresolved", "cannot store admin confirmation");
}

void executeHardening(ttlock::Session& session, const HardenRequest& request, const HardenEvidence& evidence,
                       HardenResult& result) {
    result.steps = {"skipped", "skipped", preservesAdmin(result.plan.admin) ? "preserved" : "skipped", "skipped"};
    for (auto& status : result.codes) if (std::string_view(status) == "planned") status = "skipped";
    if (!wallclock::synced()) { result.fail(0, "time_unsynced"); return; }
    if (!result.plan.executable) { result.fail(2, "admin_unresolved"); return; }
    if (lock_manager::beginHardening(request.mac) != ESP_OK) { result.fail(0, "storage_error"); return; }
    auto timed = lock_manager::synchronizeHardeningTime(session, request.mac);
    if (!timed.error.empty()) { result.fail(0, timed.error); return; }
    result.steps[0] = "done";
    for (size_t i = 0; i < evidence.passcodes.size(); ++i) {
        if (!result.plan.passcodes[i].remove) continue;
        const auto& code = evidence.passcodes[i];
        const auto deleted = session.passcodeDelete(code.type, code.code);
        if (deleted != Status::Ok) {
            result.codes[i] = "failed";
            result.fail(1, lock_manager::failure(deleted, session.lockErrorCode()).error);
            return;
        }
        result.codes[i] = "done";
        ++result.removed;
    }
    result.steps[1] = "done";
    if (!preservesAdmin(result.plan.admin)) {
        auto changed = changeHardeningAdmin(session, request, evidence, result.plan.admin);
        if (!changed.error.empty()) { result.fail(2, changed.error); return; }
        result.steps[2] = "done";
    }
    result.completion = "partial";
}

rpc::Reply harden(const cJSON* params, const rpc::Context& context) {
    HardenRequest request;
    auto reply = readHarden(params, request);
    if (reply.error.empty() && !request.dryRun && context.origin != rpc::Transport::Serial) {
        const auto presence = rpc::confirmPresence("lock.harden", context);
        if (presence != rpc::Presence::Confirmed) {
            reply = presence == rpc::Presence::SessionEnded ? rpc::fail("unauthorized", "the session ended before hardening")
                                                           : rpc::fail("confirm_timeout", "the button was not pressed within 30 s");
        } else {
            reply = readHarden(params, request);
        }
    }
    if (reply.error.empty()) {
        reply = lock_manager::runOnLockDirect(request.mac, "lock.harden", [&](ttlock::Session& session, const auto&, rpc::Reply& out) {
            HardenEvidence evidence;
            const auto read = readHardenEvidence(session, request, evidence, out);
            if (read != Status::Ok || !out.error.empty()) return read;
            auto plan = latchkey_util::planHardening(evidence.codes, evidence.labels, evidence.state.metadata,
                evidence.state.record.adminPasscode,
                (evidence.state.record.flags & store::locks::kFlagAdminPasscodeConfirmed) != 0, evidence.current);
            plan.executable = plan.executable && wallclock::synced();
            HardenResult result(plan);
            if (!wallclock::synced()) {
                result.steps[0] = "skipped";
                result.errors[0] = "time_unsynced";
            }
            if (!request.dryRun) executeHardening(session, request, evidence, result);
            auto data = result.json(request.dryRun);
            if (!data) {
                out = rpc::fail("internal", "cannot serialize hardening results; review the lock state before retrying");
            } else if (std::string_view(result.completion) == "failed") {
                out = rpc::fail("hardening_failed", "hardening stopped at the first failed step");
                out.errorData = std::move(data);
            } else {
                out = rpc::ok(data.release());
            }
            return Status::Ok;
        });
    }
    reply.target = request.mac;
    reply.audited = !request.dryRun;
    return reply;
}

}

void registerHarden() { rpc::registerMethod("lock.harden", {.job = true}, harden, checkHarden); }

}
