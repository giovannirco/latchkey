# SPDX-License-Identifier: GPL-3.0-or-later
"""PlatformIO pre-script: bundle web/ into the page that the firmware embeds.

PlatformIO builds ESP-IDF projects with SCons from CMake's code model and runs no CMake custom commands, so
this runs tools/build_web.py before the build. It writes the files that board_build.embed_files and
board_build.embed_txtfiles name in platformio.ini; src/CMakeLists.txt declares the same files with
target_add_binary_data, which puts their generated assembly into the code model.
"""

import subprocess
from pathlib import Path

Import("env")  # noqa: F821

project = Path(env.subst("$PROJECT_DIR"))  # noqa: F821
page = Path(env.subst("$BUILD_DIR")) / "web" / "index.html.gz"  # noqa: F821
bundler = project / "tools" / "build_web.py"
command = [env.subst("$PYTHONEXE"), str(bundler), str(page), "--web-dir", str(project / "web")]  # noqa: F821
if subprocess.run(command, check=False).returncode != 0:
    env.Exit(1)  # noqa: F821
