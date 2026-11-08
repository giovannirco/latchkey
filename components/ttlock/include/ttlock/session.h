// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "ttlock/bytes.h"
#include "ttlock/features.h"
#include "ttlock/frame.h"
#include "ttlock/status.h"
#include "ttlock/transport.h"
#include "ttlock/types.h"

namespace ttlock {

inline constexpr uint32_t kCommandTimeoutMs = 5000;
inline constexpr uint32_t kEnrollStepTimeoutMs = 10000;
inline constexpr size_t kMaxFramesPerReply = 16;
inline constexpr size_t kMaxListPages = 300;
inline constexpr int64_t kEarliestUsableUtc = 1704067200;
inline constexpr size_t kAdminPasscodeDigits = 7;

struct Reply;
struct LogPage;

using EventSink = std::function<void(const LockEvent&)>;
using EnrollCallback = std::function<void(const EnrollProgress&)>;
using PersistCallback = std::function<void(const LockKeys&)>;

struct PairResult {
    bool timeCalibrated = false;
    bool adminPasscodeConfirmed = false;
    bool passcodeSeedsConfirmed = false;
    uint16_t passcodeSeedYear = 0;
    std::array<CodeSecret, kCodeSecretCount> passcodeSeeds{};
};

struct PairOptions {
    std::string adminPasscode;
};

class Session {
public:
    Session(Transport& transport, Clock& clock, Random& random);

    void setEventSink(EventSink sink);

    Status pair(const LockVersion& version, LockKeys& out, PersistCallback persistEarly, PairResult& result);
    Status pair(const LockVersion& version, const PairOptions& options, LockKeys& out, PersistCallback persistEarly,
                PairResult& result);
    Status attach(const LockKeys& keys);
    const LockKeys& keys() const;
    uint8_t lockErrorCode() const;
    size_t droppedFrames() const;
    size_t lockTypeMismatches() const;
    LockVersion lastMismatchedVersion() const;

    Status unlock(OperationResult& out);
    Status lock(OperationResult& out);
    Status status(LockStatus& out);
    Status deviceInfo(DeviceInfo& out);
    Status features(uint64_t& out);
    Status syncTime();

    Status autolockGet(AutoLockSetting& out);
    Status autolockSet(uint16_t seconds);

    Status passageList(std::vector<PassageMode>& out);
    Status passageAdd(const PassageMode& mode);
    Status passageDelete(const PassageMode& mode);
    Status passageClear();

    Status passcodeList(std::vector<Passcode>& out);
    Status passcodeAdd(const Passcode& passcode);
    Status passcodeUpdate(const std::string& oldCode, const Passcode& passcode);
    Status passcodeDelete(PasscodeType type, const std::string& code);
    Status passcodeClear();
    Status setAdminPasscode(const std::string& code);
    Status adminPasscodeGet(std::string& out);
    Status adminPasscodeGetRaw(Bytes& out);

    Status fingerprintList(std::vector<Credential>& out);
    Status fingerprintEnroll(const Validity& validity, const EnrollCallback& progress, uint64_t& id);
    Status fingerprintDelete(uint64_t id);
    Status fingerprintClear();
    Status fingerprintSetValidity(uint64_t id, const Validity& validity);

    Status cardList(std::vector<Credential>& out);
    Status cardEnroll(const Validity& validity, const EnrollCallback& progress, uint64_t& number);
    Status cardDelete(uint64_t number);
    Status cardClear();
    Status cardSetValidity(uint64_t number, const Validity& validity);

    Status fetchLog(uint16_t fromSequence, std::vector<LogEntry>& out);
    Status fetchLogPage(uint16_t sequence, LogPage& out);

    Status soundGet(SoundSetting& out);
    Status soundSet(bool enabled);
    Status soundVolumeSet(uint8_t level);
    Status resetButtonGet(bool& enabled);
    Status resetButtonSet(bool enabled);
    Status remoteUnlockGet(bool& enabled);
    Status remoteUnlockSet(bool enabled);

    Status factoryReset();
    Status receiveEvent(uint32_t timeoutMs);

    Status screenPasscodeGet(bool& visible);
    Status screenPasscodeSet(bool visible);
    Status privacyLockGet(bool& enabled);
    Status privacyLockSet(bool enabled);
    Status tamperAlertGet(bool& enabled);
    Status tamperAlertSet(bool enabled);
    Status cardAddCycle(uint64_t number, const WeeklyCycle& cycle);
    Status cardClearCycles(uint64_t number);
    Status fingerprintAddCycle(uint64_t id, const WeeklyCycle& cycle);
    Status fingerprintClearCycles(uint64_t id);

private:
    Status requireKeys() const;
    Status requireFeature(Feature feature) const;
    bool timeUsable();
    LockTime localNow();
    uint32_t uniformBelow(uint32_t bound);
    uint32_t randomSecret();
    std::string randomDigits(size_t count);

    Status sendCommand(uint8_t command, const Bytes& payload);
    Status nextFrame(uint32_t timeoutMs, size_t& budget, DecodedFrame& frame);
    Status awaitPlain(uint8_t command, uint32_t timeoutMs, bool acceptEmpty, Bytes& plain);
    Status awaitData(uint8_t command, uint32_t timeoutMs, Bytes& data);
    Status request(uint8_t command, const Bytes& payload, Bytes& data);
    Status optionalRead(uint8_t command, const Bytes& payload);
    void deliver(const Reply& reply);

    Status adminLogin();
    Status beginAdmin();
    Status beginAdmin(Feature feature);
    Status adminRequest(Feature feature, uint8_t command, const Bytes& payload, Bytes& data);

    Status beforeKeysFailure(Status status, size_t mismatchesBefore) const;
    Status initialize();
    Status fetchAesKey();
    Status addAdmin();
    Status finishPairing(const std::string& chosenPasscode, const std::function<void()>& persist, PairResult& result);
    Status initPasswords(PairResult& result);
    Status controlLock(uint8_t command, OperationResult& out);
    Status enroll(bool fingerprint, const Validity& validity, const EnrollCallback& progress, uint64_t& id);
    Status switchGet(Feature feature, uint32_t item, bool& enabled);
    Status switchSet(Feature feature, uint32_t item, bool enabled);
    Status requireCyclic(Feature credential) const;

    Transport& transport_;
    Clock& clock_;
    Random& random_;
    EventSink sink_;
    LockKeys keys_;
    bool attached_ = false;
    uint8_t lockErrorCode_ = 0;
    size_t droppedFrames_ = 0;
    size_t lockTypeMismatches_ = 0;
    LockVersion lastMismatchedVersion_;
};

}
