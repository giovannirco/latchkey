// SPDX-License-Identifier: GPL-3.0-or-later
#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG

#include "lock_log.h"

#include <algorithm>
#include <utility>

#include "esp_log.h"

#include "access_requests.h"
#include "audit.h"
#include "events.h"
#include "latchkey_util/lock_log.h"
#include "latchkey_util/lock_time.h"
#include "latchkey_util/unlock_alert.h"
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

int64_t utcOf(const LogEntry& entry, int32_t offset, int64_t fallback) {
    int64_t local = 0;
    return latchkey_util::localSecondsOf(entry.time, local) ? local - offset : fallback;
}

void raise(const std::string& mac, const LogEntry& entry, latchkey_util::UnlockMethod method, int32_t offset,
           int64_t nowUtc) {
    const int64_t when = utcOf(entry, offset, nowUtc);
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

Status catchUp(ttlock::Session& session, int32_t offset, latchkey_util::WatchState& state, Entries& fresh,
               bool& more) {
    more = false;
    for (size_t pages = 0; pages < kPagesPerRead; ++pages) {
        LogPage page;
        const PageWipe wipe{page};
        const Status status = session.fetchLogPage(state.cursor, page);
        if (status != Status::Ok) {
            return status;
        }
        const latchkey_util::LogStep step = latchkey_util::stepLog(state, page, offset);
        if (step.fresh.empty()) {
            return Status::Ok;
        }
        for (const size_t index : step.fresh) {
            fresh.add(page.entries[index]);
        }
        state = step.state;
        if (!step.more) {
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

void judge(const std::string& mac, const Entries& fresh, latchkey_util::UnlockLedger& ledger, int32_t offset,
           int64_t nowUtc) {
    const std::vector<UnlockFinding> findings = ledger.judge(fresh.items(), offset, kToleranceSeconds, nowUtc);
    for (size_t i = 0; i < findings.size(); ++i) {
        const LogEntry& entry = fresh.items()[i];
        ESP_LOGD(TAG, "log record %u type %u uid %u record id %u", entry.recordNumber, entry.type,
                 static_cast<unsigned>(entry.uid), static_cast<unsigned>(entry.recordId));
        switch (findings[i].verdict) {
            case UnlockVerdict::Alert:
                raise(mac, entry, findings[i].method, offset, nowUtc);
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
}

cJSON* fetchResult(const Entries& entries, std::optional<uint16_t> since, bool more, int32_t offset) {
    std::vector<LogEntry> listed;
    for (const LogEntry& entry : entries.items()) {
        if (since.has_value() && entry.recordNumber <= *since) {
            continue;
        }
        LogEntry shown;
        shown.recordNumber = entry.recordNumber;
        shown.type = entry.type;
        shown.time = entry.time;
        shown.battery = entry.battery;
        listed.push_back(shown);
    }
    cJSON* result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "entries", lock_access::rawJson(latchkey_util::logEntriesJson(listed, offset)));
    const uint16_t last = listed.empty() ? since.value_or(0) : listed.back().recordNumber;
    cJSON_AddNumberToObject(result, "last", last);
    cJSON_AddBoolToObject(result, "more", more);
    return result;
}

}
