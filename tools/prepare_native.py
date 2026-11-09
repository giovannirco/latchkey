# SPDX-License-Identifier: GPL-3.0-or-later
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

from idf_component_tools.hash_tools.validate import validate_hash_eq_hashdir
from idf_component_tools.lock.manager import LockManager
from idf_component_tools.manifest import SolvedComponent
from idf_component_tools.sources.fetcher import ComponentFetcher


def locked_cjson(root: Path) -> SolvedComponent:
    components = []
    for target in ("esp32", "esp32s3"):
        path = root / f"dependencies.lock.{target}"
        if not path.is_file():
            raise ValueError(f"missing target dependency lock: {path.name}")
        component = LockManager(path).load().solved_components.get("espressif/cjson")
        if component is None or not component.component_hash:
            raise ValueError(f"missing locked cJSON hash: {path.name}")
        components.append(component)
    first, second = components
    if first.version != second.version or first.component_hash != second.component_hash:
        raise ValueError("target locks disagree about the cJSON dependency")
    return first


def prepare(root: Path) -> Path:
    component = locked_cjson(root)
    digest = cast(str, component.component_hash)
    cache = root / ".pio" / "native_components"
    destination = cache / digest
    if not destination.exists():
        cache.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=cache) as temporary:
            source = Path(temporary) / "cjson"
            if ComponentFetcher(component, source).download() is None:
                raise ValueError("the locked cJSON source could not be downloaded")
            validate_hash_eq_hashdir(source, digest)
            source.rename(destination)
    validate_hash_eq_hashdir(destination, digest)
    source = destination / "cJSON"
    if not all((source / name).is_file() for name in ("cJSON.c", "cJSON.h")):
        raise ValueError("the locked cJSON component has no native parser source")
    return source


if __name__ == "__main__":
    print(prepare(Path(sys.argv[1]).resolve()))
