# SPDX-License-Identifier: GPL-3.0-or-later
set(latchkey_glob_options)
if(NOT CMAKE_SCRIPT_MODE_FILE)
    list(APPEND latchkey_glob_options CONFIGURE_DEPENDS)
endif()
file(GLOB latchkey_util_sources ${latchkey_glob_options} "${CMAKE_CURRENT_LIST_DIR}/src/*.cpp")

idf_component_register(
    SRCS ${latchkey_util_sources}
    INCLUDE_DIRS "include"
    REQUIRES ttlock
)

target_compile_options(${COMPONENT_LIB} PRIVATE
    "$<$<COMPILE_LANGUAGE:CXX>:-std=gnu++20;-fno-exceptions;-fno-rtti>"
)
