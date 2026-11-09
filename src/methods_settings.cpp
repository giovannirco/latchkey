// SPDX-License-Identifier: GPL-3.0-or-later
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "mbedtls/platform_util.h"

#include "access_requests.h"
#include "latchkey_util/lock_settings.h"
#include "lock_manager.h"
#include "methods.h"
#include "rpc.h"
#include "store.h"
#include "ttlock/features.h"
#include "ttlock/session.h"
#include "ttlock/types.h"

namespace methods {

namespace {

using store::locks::Record;
using ttlock::Feature;
using ttlock::PassageMode;
using ttlock::PassageType;
using ttlock::Session;
using ttlock::Status;

constexpr int kSoundLevels = 5;
constexpr int kMinVolume = 1;
constexpr int kMaxVolume = 5;
constexpr size_t kMaxPassageDays = 8;
constexpr const char* kEnabledMessage = "enabled must be true or false";
constexpr const char* kSecondsMessage = "seconds must be a whole number from 0 (off) to 65535";
constexpr const char* kVolumeMessage = "volume must be a whole number from 1 to 5";
constexpr const char* kDaysMessage = "days lists 0 (every day) or weekdays 1 (Monday) to 7 (Sunday)";
constexpr const char* kWeeklyMessage = "only weekly passage windows can be added";
constexpr const char* kWindowMessage =
    "start and end must be HH:MM, and the passage window must end after it starts";
constexpr const char* kModeMessage =
    "a passage mode is {type: weekly or monthly, day, start: \"HH:MM\", end: \"HH:MM\"}, with month for monthly";
constexpr const char* kNoSuchMode = "no such passage mode on the lock";
constexpr const char* kBackupFirst =
    "export this lock's keys with keys.export before turning its reset button off: with the button off, the backup "
    "is the only way back if the board is lost";

using SwitchRead = Status (Session::*)(bool&);

bool readWhole(const cJSON* item, double low, double high, double& out) {
    if (!cJSON_IsNumber(item) || std::floor(item->valuedouble) != item->valuedouble || item->valuedouble < low ||
        item->valuedouble > high) {
        return false;
    }
    out = item->valuedouble;
    return true;
}

bool readEnabled(const cJSON* params, bool& out) {
    const cJSON* item = lock_access::member(params, "enabled");
    if (!cJSON_IsBool(item)) {
        return false;
    }
    out = cJSON_IsTrue(item);
    return true;
}

bool readText(const cJSON* params, const char* key, std::string& out) {
    const cJSON* item = lock_access::member(params, key);
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        return false;
    }
    out = item->valuestring;
    return true;
}

rpc::Reply onHeldLock(const std::string& mac, Feature feature, const char* action, lock_manager::LockWork work) {
    rpc::Reply gated = lock_access::gate(mac, {feature});
    if (!gated.error.empty()) {
        return lock_access::withTarget(std::move(gated), mac);
    }
    return lock_access::withTarget(lock_manager::runOnLock(mac, action, std::move(work)), mac);
}

rpc::Reply onHeldLock(const cJSON* params, Feature feature, const char* action, lock_manager::LockWork work) {
    std::string mac;
    if (!lock_access::readLock(params, mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    return onHeldLock(mac, feature, action, std::move(work));
}

cJSON* switchJson(bool enabled) {
    cJSON* result = cJSON_CreateObject();
    cJSON_AddBoolToObject(result, "enabled", enabled);
    return result;
}

cJSON* soundJson(const ttlock::SoundSetting& sound) {
    cJSON* result = cJSON_CreateObject();
    cJSON_AddBoolToObject(result, "enabled", sound.enabled);
    if (sound.volume > 0) {
        cJSON_AddNumberToObject(result, "volume", sound.volume);
    } else {
        cJSON_AddNullToObject(result, "volume");
    }
    cJSON_AddNumberToObject(result, "levels", kSoundLevels);
    return result;
}

Status readSound(Session& session, rpc::Reply& out) {
    ttlock::SoundSetting sound;
    const Status status = session.soundGet(sound);
    if (status == Status::Ok) {
        out = rpc::ok(soundJson(sound));
    }
    return status;
}

Status readModes(Session& session, std::vector<PassageMode>& modes) { return session.passageList(modes); }

rpc::Reply modesReply(const std::vector<PassageMode>& modes) {
    cJSON* result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "modes", lock_access::rawJson(latchkey_util::passageListJson(modes)));
    return rpc::ok(result);
}

Status listPassage(Session& session, rpc::Reply& out) {
    std::vector<PassageMode> modes;
    const Status status = readModes(session, modes);
    if (status == Status::Ok) {
        out = modesReply(modes);
    }
    return status;
}

Status readAutolock(Session& session, rpc::Reply& out) {
    ttlock::AutoLockSetting setting;
    const Status status = session.autolockGet(setting);
    if (status == Status::Ok) {
        out = rpc::ok(lock_access::rawJson(latchkey_util::autolockJson(setting)));
    }
    return status;
}

rpc::Handler switchGet(Feature feature, const char* action, SwitchRead read) {
    return [feature, action, read](const cJSON* params, const rpc::Context&) {
        return onHeldLock(params, feature, action, [read](Session& session, const Record&, rpc::Reply& out) {
            bool enabled = false;
            const Status status = (session.*read)(enabled);
            if (status == Status::Ok) {
                out = rpc::ok(switchJson(enabled));
            }
            return status;
        });
    };
}

rpc::Handler switchSet(Feature feature) {
    return [feature](const cJSON* params, const rpc::Context&) {
        std::string mac;
        if (!lock_access::readLock(params, mac)) {
            return lock_access::invalid(lock_access::kLockMessage);
        }
        bool enabled = false;
        if (!readEnabled(params, enabled)) {
            return lock_access::withTarget(lock_access::invalid(kEnabledMessage), mac);
        }
        Record record{};
        const bool held = lock_manager::record(mac, record);
        const bool supported = ttlock::hasFeature(record.features, feature);
        mbedtls_platform_zeroize(&record, sizeof(record));
        if (!held) {
            return lock_access::withTarget(rpc::fail("not_paired", "the board has no keys for this lock"), mac);
        }
        if (!supported) {
            return lock_access::withTarget(rpc::fail("unsupported", "the lock does not report this switch"), mac);
        }
        if (feature == Feature::ResetButton && !enabled) {
            return lock_access::withTarget(rpc::fail("backup_required", kBackupFirst), mac);
        }
        return lock_access::withTarget(rpc::fail("unverified", "switch writes are not yet verified on this lock"), mac);
    };
}

rpc::Reply autolockGet(const cJSON* params, const rpc::Context&) {
    return onHeldLock(params, Feature::AutoLock, "lock.autolock.get",
                      [](Session& session, const Record&, rpc::Reply& out) { return readAutolock(session, out); });
}

rpc::Reply autolockSet(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!lock_access::readLock(params, mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    double seconds = 0;
    if (!readWhole(lock_access::member(params, "seconds"), 0, latchkey_util::kMaxAutolockSeconds, seconds)) {
        return lock_access::withTarget(lock_access::invalid(kSecondsMessage), mac);
    }
    const auto wanted = static_cast<uint32_t>(seconds);
    return onHeldLock(mac, Feature::AutoLock, "lock.autolock.set",
                      [wanted](Session& session, const Record&, rpc::Reply& out) {
                          ttlock::AutoLockSetting range;
                          Status status = session.autolockGet(range);
                          if (status != Status::Ok) {
                              return status;
                          }
                          if (!latchkey_util::autolockAllowed(wanted, range)) {
                              const std::string message = "auto-lock is 0 (off) or " +
                                                          std::to_string(range.minSeconds) + " to " +
                                                          std::to_string(range.maxSeconds) + " s on this lock";
                              out = lock_access::invalid(message.c_str());
                              return Status::Ok;
                          }
                          status = session.autolockSet(static_cast<uint16_t>(wanted));
                          return status == Status::Ok ? readAutolock(session, out) : status;
                      });
}

rpc::Reply passageList(const cJSON* params, const rpc::Context&) {
    return onHeldLock(params, Feature::PassageMode, "lock.passage.list",
                      [](Session& session, const Record&, rpc::Reply& out) { return listPassage(session, out); });
}

bool readWindow(const cJSON* params, PassageType type, int day, PassageMode& out) {
    std::string start;
    std::string end;
    return readText(params, "start", start) && readText(params, "end", end) &&
           latchkey_util::makePassage(type, day, start, end, out);
}

rpc::Reply readNewWindows(const cJSON* params, std::vector<PassageMode>& out) {
    const cJSON* type = lock_access::member(params, "type");
    if (!lock_access::absent(type) && (!cJSON_IsString(type) || std::string_view(type->valuestring) != "weekly")) {
        return lock_access::invalid(kWeeklyMessage);
    }
    const cJSON* days = lock_access::member(params, "days");
    if (!cJSON_IsArray(days) || cJSON_GetArraySize(days) == 0 ||
        static_cast<size_t>(cJSON_GetArraySize(days)) > kMaxPassageDays) {
        return lock_access::invalid(kDaysMessage);
    }
    const cJSON* item = nullptr;
    cJSON_ArrayForEach(item, days) {
        double day = 0;
        if (!readWhole(item, 0, 7, day)) {
            return lock_access::invalid(kDaysMessage);
        }
        PassageMode mode;
        if (!readWindow(params, PassageType::Weekly, static_cast<int>(day), mode) ||
            !latchkey_util::runsForward(mode)) {
            return lock_access::invalid(kWindowMessage);
        }
        if (std::find(out.begin(), out.end(), mode) == out.end()) {
            out.push_back(mode);
        }
    }
    return rpc::ok();
}

rpc::Reply passageAdd(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!lock_access::readLock(params, mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    std::vector<PassageMode> wanted;
    rpc::Reply problem = readNewWindows(params, wanted);
    if (!problem.error.empty()) {
        return lock_access::withTarget(std::move(problem), mac);
    }
    return onHeldLock(mac, Feature::PassageMode, "lock.passage.add",
                      [wanted](Session& session, const Record&, rpc::Reply& out) {
                          std::vector<PassageMode> modes;
                          Status status = readModes(session, modes);
                          if (status != Status::Ok) {
                              return status;
                          }
                          for (const PassageMode& mode : wanted) {
                              if (std::find(modes.begin(), modes.end(), mode) != modes.end()) {
                                  continue;
                              }
                              status = session.passageAdd(mode);
                              if (status != Status::Ok) {
                                  return status;
                              }
                          }
                          return listPassage(session, out);
                      });
}

rpc::Reply readListedMode(const cJSON* params, PassageMode& out) {
    std::string name;
    PassageType type = PassageType::Weekly;
    double day = 0;
    if (!readText(params, "type", name) || !latchkey_util::passageTypeOf(name, type) ||
        !readWhole(lock_access::member(params, "day"), 0, 31, day) ||
        !readWindow(params, type, static_cast<int>(day), out)) {
        return lock_access::invalid(kModeMessage);
    }
    const cJSON* month = lock_access::member(params, "month");
    double value = 0;
    if (type == PassageType::Monthly && !lock_access::absent(month)) {
        if (!readWhole(month, 0, 12, value)) {
            return lock_access::invalid(kModeMessage);
        }
        out.month = static_cast<uint8_t>(value);
    }
    return rpc::ok();
}

rpc::Reply passageDelete(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!lock_access::readLock(params, mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    PassageMode mode;
    rpc::Reply problem = readListedMode(params, mode);
    if (!problem.error.empty()) {
        return lock_access::withTarget(std::move(problem), mac);
    }
    return onHeldLock(mac, Feature::PassageMode, "lock.passage.delete",
                      [mode](Session& session, const Record&, rpc::Reply& out) {
                          std::vector<PassageMode> modes;
                          Status status = readModes(session, modes);
                          if (status != Status::Ok) {
                              return status;
                          }
                          if (std::find(modes.begin(), modes.end(), mode) == modes.end()) {
                              out = lock_access::invalid(kNoSuchMode);
                              return Status::Ok;
                          }
                          status = session.passageDelete(mode);
                          return status == Status::Ok ? listPassage(session, out) : status;
                      });
}

rpc::Reply passageClear(const cJSON* params, const rpc::Context&) {
    return onHeldLock(params, Feature::PassageMode, "lock.passage.clear",
                      [](Session& session, const Record&, rpc::Reply& out) {
                          const Status status = session.passageClear();
                          if (status == Status::Ok) {
                              out = modesReply({});
                          }
                          return status;
                      });
}

rpc::Reply soundGet(const cJSON* params, const rpc::Context&) {
    return onHeldLock(params, Feature::AudioManagement, "lock.sound.get",
                      [](Session& session, const Record&, rpc::Reply& out) { return readSound(session, out); });
}

rpc::Reply soundSet(const cJSON* params, const rpc::Context&) {
    std::string mac;
    if (!lock_access::readLock(params, mac)) {
        return lock_access::invalid(lock_access::kLockMessage);
    }
    bool enabled = false;
    if (!readEnabled(params, enabled)) {
        return lock_access::withTarget(lock_access::invalid(kEnabledMessage), mac);
    }
    std::optional<uint8_t> volume;
    const cJSON* item = lock_access::member(params, "volume");
    if (!lock_access::absent(item)) {
        double level = 0;
        if (!readWhole(item, kMinVolume, kMaxVolume, level)) {
            return lock_access::withTarget(lock_access::invalid(kVolumeMessage), mac);
        }
        volume = static_cast<uint8_t>(level);
    }
    return onHeldLock(mac, Feature::AudioManagement, "lock.sound.set",
                      [enabled, volume](Session& session, const Record&, rpc::Reply& out) {
                          Status status = session.soundSet(enabled);
                          if (status == Status::Ok && volume.has_value()) {
                              status = session.soundVolumeSet(*volume);
                          }
                          return status == Status::Ok ? readSound(session, out) : status;
                      });
}


}

void registerSettings() {
    constexpr rpc::Access kRead{.audited = false, .job = true};
    constexpr rpc::Access kWrite{.job = true};
    rpc::registerMethod("lock.autolock.get", kRead, autolockGet);
    rpc::registerMethod("lock.autolock.set", kWrite, autolockSet);
    rpc::registerMethod("lock.passage.list", kRead, passageList);
    rpc::registerMethod("lock.passage.add", kWrite, passageAdd);
    rpc::registerMethod("lock.passage.delete", kWrite, passageDelete);
    rpc::registerMethod("lock.passage.clear", kWrite, passageClear);
    rpc::registerMethod("lock.sound.get", kRead, soundGet);
    rpc::registerMethod("lock.sound.set", kWrite, soundSet);
    rpc::registerMethod("lock.resetButton.get", kRead,
                        switchGet(Feature::ResetButton, "lock.resetButton.get", &Session::resetButtonGet));
    const rpc::Handler resetButtonSet = switchSet(Feature::ResetButton);
    rpc::registerMethod("lock.resetButton.set", {.needsButton = true, .job = true}, resetButtonSet, resetButtonSet);
    rpc::registerMethod("lock.privacyLock.get", kRead,
                        switchGet(Feature::PrivacyLock, "lock.privacyLock.get", &Session::privacyLockGet));
    rpc::registerMethod("lock.privacyLock.set", kWrite,
                        switchSet(Feature::PrivacyLock));
    rpc::registerMethod("lock.tamperAlert.get", kRead,
                        switchGet(Feature::TamperAlert, "lock.tamperAlert.get", &Session::tamperAlertGet));
    rpc::registerMethod("lock.tamperAlert.set", kWrite,
                        switchSet(Feature::TamperAlert));
}

}
