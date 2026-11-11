// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
struct esp_app_desc_t { char version[32]; };
const esp_app_desc_t* esp_app_get_description();
