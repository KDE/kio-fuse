# SPDX-FileCopyrightText: 2026 Chinmoy Pradhan <chinmoy.pradhan@machinesoul.in>
# SPDX-License-Identifier: GPL-3.0-or-later

find_program(fusermount3_EXE fusermount3)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(fusermount3
    FOUND_VAR
        fusermount3_FOUND
    REQUIRED_VARS
        fusermount3_EXE
)
