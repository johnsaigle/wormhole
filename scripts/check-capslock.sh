#!/usr/bin/env sh

set -e

NODE_DIR="node"
# A snapshot of the node's current dependency capabilities. It should be updated whenever a dependency is added
# or whenever a dependency's capabilities change legitimately.
SNAPSHOT=".capslock/capslock-node-snapshot.json"

# capslock must be run in the same directory as the code its scanning
cd $NODE_DIR
capslock -output=compare "../$NODE_DIR/../$SNAPSHOT"
status=$? 

if [ ! $status -eq 0 ]; then
   "ERROR: capslock detected a change in program capabilities"
fi

exit $status
