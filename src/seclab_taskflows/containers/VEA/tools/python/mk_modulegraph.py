#!/usr/bin/env python3

# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

import sys
import ast
import importlib.util
import logging
from pathlib import Path
import subprocess
import json


def find_module_info(name, package=None):
    """Wrapper around importlib.util.find_spec that catches the error if the module isn't found"""
    #print('find_spec', name, package)
    try:
        spec = importlib.util.find_spec(name, package)
        if spec and spec.origin:
            yield {"name": spec.name, "origin": spec.origin, "parent": spec.parent}
    except:
        logging.warning('not found %s %s', name, package)
        pass

def get_imports(spec, visited):
    path = spec['origin']
    if path in visited:
        return
    visited[path] = spec
    try:
        with open(path) as fh:        
            tree = ast.parse(fh.read(), path)
    except Exception as e:
        logging.warning('failed to parse %s %s', path, e)
        return

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                find_module_info(n.name, spec['parent'])
        elif isinstance(node, ast.ImportFrom):
            # If the import is relative, for example 'from ..foo.bar import a as b, c',
            # then the parser strips of the leading '.' characters and stores the
            # count in `node.level`. But `importlib.util.find_spec` needs the module name
            # with the leading '.' characters, so we reconstruct it here:
            module_name = "." * node.level + (node.module or "")
            for module_spec in find_module_info(module_name, spec['parent']):
                yield module_spec
                for n in node.names:
                    # 'from x import y' might be an import of a module named 'x.y', or
                    # it might be an import of a method named 'y' from module 'x'.
                    find_module_info("." + n.name, module_spec['name'])
        else:
            continue

if __name__ == "__main__":
    worklist = []
    with open(sys.argv[1]) as fh:
        for module in fh.read().splitlines():
            for spec in find_module_info(module):
                worklist.append(spec)

    visited = {}
    edges = []
    while worklist:
        spec = worklist.pop()
        for child in get_imports(spec, visited):
            worklist.append(child)
            edges.append((spec, child))

    # Write the edges in CSV format
    with open(sys.argv[2], 'w', encoding="utf-8") as fh:
        for parent, child in edges:
            parent_name = parent['name']
            child_name = child['name']
            fh.write(f'"{parent_name}","{child_name}"\n')
