# SPDX-License-Identifier: GPL-3.0-or-later
import subprocess
from pathlib import Path

globals()["Import"]("env")
native_env = globals()["env"]

project = Path(native_env.subst("$PROJECT_DIR"))
prepared = subprocess.run(
    [
        "uv",
        "run",
        "--no-project",
        "--with",
        "idf-component-manager==3.1.2",
        "python",
        str(project / "tools" / "prepare_native.py"),
        str(project),
    ],
    check=True,
    capture_output=True,
    text=True,
    timeout=120,
)
source = prepared.stdout.strip()
native_env.Append(CPPPATH=[source])
parser = native_env.Clone()
parser.ProcessUnFlags("-std=gnu++20 -fno-rtti")
native_env.Append(
    LIBS=[parser.BuildLibrary("$BUILD_DIR/cjson", source, src_filter="+<cJSON.c>")]
)
