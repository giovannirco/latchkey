// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "latchkey_util/key_restore.h"
#include "store.h"

namespace key_store {

class Restore final : public latchkey_util::RestoreStorage {
public:
    bool readJournal(latchkey_util::RestoreJournal& out, bool& present) override;
    bool countRecords(size_t& out) override;
    bool containsIdentity(std::string_view mac, bool& out) override;
    bool capacity(size_t& availableEntries, size_t& reservedEntries) override;
    size_t recordBytes() const override;
    bool writeJournal(const latchkey_util::RestoreJournal& journal) override;
    bool writePart(const latchkey_util::BackupLock& lock, latchkey_util::RestorePart part) override;
    bool erasePart(std::string_view mac, latchkey_util::RestorePart part) override;
    bool clearJournal() override;
};

esp_err_t recover();
bool makeRecord(const latchkey_util::BackupLock& lock, store::locks::Record& record);
esp_err_t snapshot(std::string_view mac, latchkey_util::SensitiveBuffer& plaintext,
                   latchkey_util::RestoreJournal& identities);
esp_err_t loadRecord(std::string_view mac, store::locks::Record& out);
esp_err_t loadMetadata(std::string_view mac, latchkey_util::LockMetadata& out);
esp_err_t saveMetadata(std::string_view mac, const latchkey_util::LockMetadata& metadata);
esp_err_t eraseMetadata(std::string_view mac);
esp_err_t eraseAllMetadata();
esp_err_t checkErase(std::string_view mac);
esp_err_t loadSeeds(std::string_view mac, latchkey_util::SeedTable& out, bool& present);

}
