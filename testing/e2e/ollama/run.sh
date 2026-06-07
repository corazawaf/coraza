#!/usr/bin/env bash
# testing/e2e/ollama/run.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL="${OLLAMA_MODEL:-tinyllama}"
OLLAMA_URL="http://localhost:11434"

cleanup() {
  # Omit --volumes to preserve the model cache between runs
  docker compose -f "$SCRIPT_DIR/compose.yml" down
}
trap cleanup EXIT

docker compose -f "$SCRIPT_DIR/compose.yml" up -d

echo "Waiting for Ollama..."
timeout 120 bash -c "until curl -sf \"$OLLAMA_URL/api/version\" >/dev/null 2>&1; do sleep 2; done"
echo "Ollama ready."

echo "Pulling model: $MODEL"
docker compose -f "$SCRIPT_DIR/compose.yml" exec ollama ollama pull "$MODEL"
echo "Model ready."

echo "Running e2e tests..."
cd "$SCRIPT_DIR/../../.."
OLLAMA_BASE_URL="$OLLAMA_URL" OLLAMA_MODEL="$MODEL" \
  go test -v -timeout 180s -run TestOllamaStreaming ./testing/e2e/ollama/...
echo "Done."
