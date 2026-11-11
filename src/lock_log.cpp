// SPDX-License-Identifier: GPL-3.0-or-later
#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG

#include "lock_log.h"

#include <algorithm>
#include <utility>

#include "esp_log.h"
#include "mbedtls/platform_util.h"

#include "access_requests.h"
#include "audit.h"
#include "events.h"
#include "hmac.h"
#include "latchkey_util/lock_log.h"
#include "latchkey_util/lock_time.h"
#include "latchkey_util/unlock_alert.h"
#include "lock_manager.h"
#include "rpc.h"
#include "ttlock/commands.h"

namespace lock_log {

namespace {

using latchkey_util::UnlockFinding;
using latchkey_util::UnlockVerdict;
using ttlock::LogEntry;
using ttlock::LogPage;
using ttlock::Status;

constexpr const char* TAG = "lock_log";

struct PageWipe {
    LogPage& page;

    ~PageWipe() {
        for (LogEntry& entry : page.entries) {
            lock_access::wipe(entry.credential);
            lock_access::wipe(entry.newCredential);
        }
    }
};

int64_t utcOf(const LogEntry& entry, int32_t offset) {
    int64_t local = 0;
    return latchkey_util::localSecondsOf(entry.time, local) ? local - offset : 0;
}

bool raise(const std::string& mac, const LogEntry& entry, latchkey_util::UnlockMethod method, int32_t offset,
           bool stopOnFailure) {
    const int64_t when = utcOf(entry, offset);
    latchkey_util::LockAlert alert;
    alert.time = static_cast<uint32_t>(when > 0 ? when : 0);
    alert.seq = entry.recordNumber;
    alert.type = entry.type;
    alert.method = method;
    bool added = false;
    const esp_err_t stored = lock_manager::rememberAlert(mac, alert, added, stopOnFailure);
    if (stored != ESP_OK) {
        ESP_LOGE(TAG, "cannot store the unlock alert: %s", esp_err_to_name(stored));
    }
    if (!added) {
        return stored == ESP_OK;
    }
    const char* name = latchkey_util::toString(method);
    ESP_LOGW(TAG, "unlock alert for %s: log record %u, type %u, %s", mac.c_str(), entry.recordNumber, entry.type,
             name);
    cJSON* data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "lock", mac.c_str());
    cJSON_AddStringToObject(data, "method", name);
    cJSON_AddNumberToObject(data, "time", static_cast<double>(when));
    cJSON_AddNumberToObject(data, "seq", entry.recordNumber);
    cJSON_AddNumberToObject(data, "type", entry.type);
    events::publish("lock.alert", data);
    audit::append({static_cast<uint32_t>(when > 0 ? when : 0), rpc::Transport::Board, "lock.alert", mac, name});
    return stored == ESP_OK;
}

}

Entries::~Entries() {
    for (LogEntry& entry : items_) {
        lock_access::wipe(entry.credential);
        lock_access::wipe(entry.newCredential);
    }
}

bool Entries::has(uint16_t seq) const {
    return std::any_of(items_.begin(), items_.end(), [seq](const LogEntry& entry) { return entry.recordNumber == seq; });
}

void Entries::add(LogEntry& entry) {
    if (has(entry.recordNumber)) {
        return;
    }
    const auto place = std::find_if(items_.begin(), items_.end(), [&entry](const LogEntry& item) {
        return item.recordNumber > entry.recordNumber;
    });
    items_.insert(place, std::move(entry));
}

Status findEnd(ttlock::Session& session, int32_t offset, latchkey_util::WatchState& state) {
    latchkey_util::LogEndSearch search;
    while (!search.done()) {
        LogPage page;
        const PageWipe wipe{page};
        const Status status = session.fetchLogPage(search.slot(), page);
        if (status != Status::Ok) {
            return status;
        }
        search.read(page, offset);
    }
    state = search.baseline(state);
    ESP_LOGI(TAG, "the log ends before record %u (%u reads)", state.cursor, static_cast<unsigned>(search.reads()));
    return Status::Ok;
}

bool report(const std::string& mac, const LogPage& page, const latchkey_util::PageJudgement& judged,
            const latchkey_util::WatchState& state, int32_t offset, bool stopOnFailure);

Status catchUp(ttlock::Session& session, const std::string& mac, int32_t offset, latchkey_util::LogWatch& watch,
               Entries& fresh, bool& more, int64_t nowUtc, bool stopOnFailure) {
    more = false;
    for (size_t pages = 0; pages < kPagesPerRead; ++pages) {
        LogPage page;
        const PageWipe wipe{page};
        const Status status = session.fetchLogPage(watch.state().cursor, page);
        if (status != Status::Ok) {
            return status;
        }
        latchkey_util::LogWatch staged = watch;
        const latchkey_util::PageJudgement judged = staged.readPage(page, offset, kToleranceSeconds, nowUtc);
        if (judged.fresh.empty()) {
            return Status::Ok;
        }
        if (!report(mac, page, judged, staged.state(), offset, stopOnFailure)) {
            return Status::Busy;
        }
        watch = std::move(staged);
        for (const size_t index : judged.fresh) {
            fresh.add(page.entries[index]);
        }
        if (!judged.more) {
            return Status::Ok;
        }
    }
    more = true;
    return Status::Ok;
}

Status readSlots(ttlock::Session& session, uint16_t from, uint16_t to, Entries& out) {
    for (uint32_t slot = from; slot < to; ++slot) {
        if (out.has(static_cast<uint16_t>(slot))) {
            continue;
        }
        LogPage page;
        const PageWipe wipe{page};
        const Status status = session.fetchLogPage(static_cast<uint16_t>(slot), page);
        if (status != Status::Ok) {
            return status;
        }
        for (LogEntry& entry : page.entries) {
            if (entry.recordNumber >= from && entry.recordNumber < to) {
                out.add(entry);
            }
        }
    }
    return Status::Ok;
}

bool report(const std::string& mac, const LogPage& page, const latchkey_util::PageJudgement& judged,
            const latchkey_util::WatchState& state, int32_t offset, bool stopOnFailure) {
    const std::vector<UnlockFinding>& findings = judged.findings;
    bool saved = true;
    for (size_t i = 0; i < findings.size(); ++i) {
        const LogEntry& entry = page.entries[judged.fresh[i]];
        ESP_LOGD(TAG, "log record %u type %u uid %u record id %u", entry.recordNumber, entry.type,
                 static_cast<unsigned>(entry.uid), static_cast<unsigned>(entry.recordId));
        switch (findings[i].verdict) {
            case UnlockVerdict::Alert:
                if (!raise(mac, entry, findings[i].method,
                           latchkey_util::recordOffset(state, entry.recordNumber, offset), stopOnFailure)) {
                    if (stopOnFailure) return false;
                    saved = false;
                }
                break;
            case UnlockVerdict::Latchkey:
                ESP_LOGI(TAG, "log record %u: the board's own unlock", entry.recordNumber);
                break;
            case UnlockVerdict::Reported:
                ESP_LOGI(TAG, "log record %u: unlocked by %s", entry.recordNumber,
                         latchkey_util::toString(findings[i].method));
                break;
            case UnlockVerdict::NotUnlock:
                break;
        }
    }
    return saved;
}

rpc::Reply fetchResult(const Entries& entries, std::optional<uint16_t> since, uint32_t until, bool more,
                        const latchkey_util::WatchState& state, int32_t offset, const store::locks::Record& record) {
    latchkey_util::LogLabels labels;
    const esp_err_t loaded = lock_manager::loadLogLabels(record.mac, labels);
    if (loaded != ESP_OK) return lock_access::labelsUnreadable(loaded);
    std::string listed = "[";
    uint16_t last = since.value_or(0);
    bool first = true;
    const uint32_t from = since.has_value() ? *since + 1U : until > kShownSlots ? until - kShownSlots : 0;
    for (const LogEntry& entry : entries.items()) {
        if (entry.recordNumber < from || entry.recordNumber >= until) {
            continue;
        }
        latchkey_util::LockAesKey key;
        std::copy(std::begin(record.aesKey), std::end(record.aesKey), key.begin());
        std::string rendered;
        const bool ready = latchkey_util::logEntryJson(entry, latchkey_util::recordOffset(state, entry.recordNumber, offset),
                                                       labels, key, hmac::sha256, rendered);
        mbedtls_platform_zeroize(key.data(), key.size());
        if (!ready) return rpc::fail("internal", "cannot compute a log credential id");
        if (!first) listed += ',';
        first = false;
        listed += rendered;
        last = entry.recordNumber;
    }
    listed += ']';
    rpc::Json result(cJSON_CreateObject());
    rpc::Json items(lock_access::rawJson(listed));
    if (!result || !items || !cJSON_AddItemToObject(result.get(), "entries", items.get())) {
        return rpc::fail("internal", "cannot allocate the lock log response");
    }
    items.release();
    if (!cJSON_AddNumberToObject(result.get(), "last", last) || !cJSON_AddBoolToObject(result.get(), "more", more)) {
        return rpc::fail("internal", "cannot allocate the lock log response");
    }
    return rpc::ok(result.release());
}

}
