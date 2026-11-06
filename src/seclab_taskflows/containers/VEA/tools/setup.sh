#!/bin/bash

# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

VEA_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo $VEA_SCRIPT_DIR

./venv/bin/pip install -e /workspace/code
./venv/bin/pip install -r "$VEA_SCRIPT_DIR/requirements.txt"
./venv/bin/python "$VEA_SCRIPT_DIR/python/list_modules.py" /workspace/code modulelist.txt
./venv/bin/python "$VEA_SCRIPT_DIR/python/mk_modulegraph.py" modulelist.txt modulegraph.csv
