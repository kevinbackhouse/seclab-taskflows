#!/usr/bin/env python3

# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

# A tool for listing all the 

import pathlib
import sys
import tempfile
import zipfile
import build

def build_and_list_modules(dir: str = ".") -> list[str]:
    """Build the project and then use the wheel to get the list of module names."""
    dir = pathlib.Path(dir).resolve().as_posix()

    with tempfile.TemporaryDirectory() as tmp:
        wheel_name = build.ProjectBuilder(dir).build("wheel", tmp)
        wheel_path = pathlib.Path(tmp) / wheel_name

        modules: set[str] = set()
        with zipfile.ZipFile(wheel_path) as zf:
            for p in zf.namelist():
                if ".dist-info/" in p or ".data/" in p:
                    continue
                if not p.endswith(".py"):
                    continue
                p = p[:-3]
                parts = p.split("/")
                modules.add(".".join(parts))

    return sorted(modules)

if __name__ == "__main__":
    with open(sys.argv[2], 'w', encoding="utf-8") as fh:
        for m in build_and_list_modules(sys.argv[1]):
            fh.write(f'{m}\n')
