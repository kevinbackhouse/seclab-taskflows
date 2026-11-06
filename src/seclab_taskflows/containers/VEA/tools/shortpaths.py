#!/usr/bin/env python3

# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

import sys
import csv
import networkx

if __name__ == "__main__":
    with open(sys.argv[1]) as fh:
        sources = fh.read().splitlines()

    graph = networkx.DiGraph()
    with open(sys.argv[2]) as fh:
        for row in csv.reader(fh):
            source = row[0]
            target = row[1]
            graph.add_edge(source, target)
    
    # Write the edges in CSV format
    with open(sys.argv[3], 'w', encoding="utf-8") as fh:
        target = sys.argv[4]
        for source in sources:
            try:
                path = networkx.shortest_path(graph, source=source, target=target)
                fh.write(" -> ".join(path) + "\n")
            except:
                pass
