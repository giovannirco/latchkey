# SPDX-License-Identifier: GPL-3.0-or-later
idf_build_get_property(python PYTHON)
set(latchkey_root "${CMAKE_CURRENT_LIST_DIR}/..")
set(web_page "${CMAKE_BINARY_DIR}/web/index.html.gz")
set(web_policy "${web_page}.csp.txt")
file(GLOB web_sources CONFIGURE_DEPENDS "${latchkey_root}/web/*")

add_custom_command(
    OUTPUT "${web_page}" "${web_policy}"
    COMMAND "${python}" "${latchkey_root}/tools/build_web.py" "${web_page}" --web-dir "${latchkey_root}/web"
    DEPENDS ${web_sources} "${latchkey_root}/tools/build_web.py"
    VERBATIM)

target_add_binary_data(${COMPONENT_LIB} "${web_page}" BINARY)
target_add_binary_data(${COMPONENT_LIB} "${web_policy}" TEXT)
