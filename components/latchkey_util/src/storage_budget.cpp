// SPDX-License-Identifier: GPL-3.0-or-later
#include "latchkey_util/storage_budget.h"

namespace latchkey_util {

namespace {

constexpr size_t kBlobIndexEntries = 1;
constexpr size_t kChunkHeaderEntries = 1;
constexpr size_t kSequenceEntries = 1;
constexpr size_t kWritesPerPairing = 2;

}

size_t nvsBlobEntries(size_t bytes) {
    return kBlobIndexEntries + kChunkHeaderEntries + (bytes + kNvsEntryBytes - 1) / kNvsEntryBytes;
}

size_t auditRecordsLeft(uint32_t nextSeq, uint32_t capacity) {
    const uint32_t written = nextSeq > 0 ? nextSeq - 1 : 0;
    return written >= capacity ? 0 : capacity - written;
}

size_t reservedEntries(const StorageNeeds& needs) {
    return needs.auditRecordsLeft * nvsBlobEntries(needs.auditRecordBytes) + kSequenceEntries +
           kWritesPerPairing * (nvsBlobEntries(needs.lockRecordBytes) + nvsBlobEntries(needs.seedTableBytes)) +
           needs.spareEntries;
}

bool fitsAboveReserve(size_t availableEntries, size_t blobBytes, size_t reserved) {
    const size_t needed = nvsBlobEntries(blobBytes);
    return availableEntries >= needed && availableEntries - needed >= reserved;
}

}
