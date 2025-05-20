#!/bin/bash

set -e

echo "🚀 Building images using buildpacks..."

pack build gateway --path ./gateway
pack build resourceserver --path ./resourceServer

echo "✅ Done. You can now run: docker-compose up"
# error: release version 24 not supported
# Paketo Buildpacks does not yet support JDK 24