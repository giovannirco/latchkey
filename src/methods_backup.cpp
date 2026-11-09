// SPDX-License-Identifier: GPL-3.0-or-later
#include "backup.h"
#include "backup_crypto.h"
#include "lock_manager.h"
#include "methods.h"

namespace methods {
namespace {

rpc::Reply exportKeys(cJSON* params, const rpc::Context&) {
    return lock_manager::runStorage("keys.export", [params](auto&, auto& publication) {
        backup_crypto::PsaCrypto crypto;
        return backup::exportKeys(params, crypto, publication);
    });
}

rpc::Reply importKeys(cJSON* params, const rpc::Context&) {
    return lock_manager::runStorage("keys.import", [params](auto& storage, auto& publication) {
        backup_crypto::PsaCrypto crypto;
        return backup::importKeys(params, crypto, storage, publication);
    });
}

}

void registerBackup() {
    rpc::registerMethod("keys.export", {.needsButton = true, .job = true}, exportKeys, backup::checkExport);
    rpc::registerMethod("keys.import", {.needsButton = true, .job = true}, importKeys, backup::checkImport);
}

}
