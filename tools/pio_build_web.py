# SPDX-License-Identifier: GPL-3.0-or-later
"""PlatformIO pre-script: bundle web/ into the page that the firmware embeds.

PlatformIO builds ESP-IDF projects with SCons from CMake's code model, so the custom command in
src/web_assets.cmake does not run under it. This runs the same tools/build_web.py step before the build,
writing the files that board_build.embed_files and board_build.embed_txtfiles name in platformio.ini.
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
