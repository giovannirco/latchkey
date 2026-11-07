# SPDX-License-Identifier: GPL-3.0-or-later
idf_component_register(
    SRCS "main.cpp" "board.cpp"
    INCLUDE_DIRS "."
    PRIV_REQUIRES esp_app_format
)
