# SPDX-License-Identifier: GPL-3.0-or-later
file(GLOB latchkey_util_sources "${CMAKE_CURRENT_LIST_DIR}/src/*.cpp")

idf_component_register(
    SRCS ${latchkey_util_sources}
    INCLUDE_DIRS "include"
    REQUIRES ttlock
)

target_compile_options(${COMPONENT_LIB} PRIVATE
    "$<$<COMPILE_LANGUAGE:CXX>:-std=gnu++20;-fno-exceptions;-fno-rtti>"
)
