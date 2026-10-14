#!/bin/bash
# Load the estate once with the offline bulk importer, then serve it read-only.
set -euo pipefail
if [ ! -f /data/.estate-imported ]; then
  neo4j-admin database import full neo4j --overwrite-destination \
    --nodes=/seed/nodes.csv --relationships=/seed/rels.csv
  touch /data/.estate-imported
  chown -R neo4j:neo4j /data
fi
exec /startup/docker-entrypoint.sh neo4j
