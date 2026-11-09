// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "latchkey_util/key_backup.h"
#include "lock_manager.h"
#include "rpc.h"

namespace backup {

rpc::Reply checkExport(cJSON* params, const rpc::Context& context);
rpc::Reply checkImport(cJSON* params, const rpc::Context& context);
rpc::Reply exportKeys(cJSON* params, latchkey_util::BackupCrypto& crypto,
                       lock_manager::StoragePublication& publication);
rpc::Reply importKeys(cJSON* params, latchkey_util::BackupCrypto& crypto,
                       latchkey_util::RestoreStorage& storage, lock_manager::StoragePublication& publication);

}
