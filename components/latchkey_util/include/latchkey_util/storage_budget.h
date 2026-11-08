// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>

namespace latchkey_util {

inline constexpr size_t kNvsEntryBytes = 32;

struct StorageNeeds {
    size_t auditRecordsLeft = 0;
    size_t auditRecordBytes = 0;
    size_t lockRecordBytes = 0;
    size_t seedTableBytes = 0;
    size_t spareEntries = 0;
    size_t watchStateBytes = 0;
    size_t watchStates = 0;
};

size_t nvsBlobEntries(size_t bytes);

size_t auditRecordsLeft(uint32_t nextSeq, uint32_t capacity);

size_t reservedEntries(const StorageNeeds& needs);

bool fitsAboveReserve(size_t availableEntries, size_t blobBytes, size_t reserved);

}
