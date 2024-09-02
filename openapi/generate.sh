#!/bin/sh

set -e

# Download JAR file
GENERATOR_JAR_URL="https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/7.7.0/openapi-generator-cli-7.7.0.jar"
GENERATOR_JAR_PATH="openapi/generator.jar"
if ! [ -f "$GENERATOR_JAR_PATH" ]; then
    curl -L -o "$GENERATOR_JAR_PATH" "$GENERATOR_JAR_URL"
fi

# Enable post-processing with ruff's formatter
export PYTHON_POST_PROCESS_FILE="ruff format"

# Generate client
java -jar "$GENERATOR_JAR_PATH" generate \
    -i "openapi/schema.json" \
    -g python \
    --enable-post-process-file \
    --global-property models,apis,apiTests=false,modelTests=false,apiDocs=false,modelDocs=false,supportingFiles \
    --additional-properties packageName=bugprove.internal,library=asyncio \
    --template-dir "openapi/templates" \
    -o "src"

# Remove hardcoded folder (https://stackoverflow.com/a/71454918)
rm -rf "src/.openapi-generator"