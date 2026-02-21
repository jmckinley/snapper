#!/bin/bash
# =============================================================================
# Snapper Shadow AI Discovery Agent
# =============================================================================
#
# Lightweight scanner deployable to any Linux host. Detects unauthorized AI
# tools via process, network, and container scanning, then reports findings
# to a central Snapper instance.
#
# Usage:
#   SNAPPER_URL=https://snapper.example.com \
#   SNAPPER_API_KEY=snp_xxx \
#   HOST_ID=$(hostname) \
#   bash shadow-ai-scanner.sh
#
# Deploy: copy to target host, set env vars, add to cron:
#   */5 * * * * SNAPPER_URL=... SNAPPER_API_KEY=... /opt/shadow-ai-scanner.sh
# =============================================================================

set -euo pipefail

SNAPPER_URL="${SNAPPER_URL:?Set SNAPPER_URL to your Snapper instance URL}"
SNAPPER_API_KEY="${SNAPPER_API_KEY:-}"
HOST_ID="${HOST_ID:-$(hostname)}"

REPORT_ENDPOINT="${SNAPPER_URL}/api/v1/shadow-ai/report"

# --- Known AI domains ---
AI_DOMAINS=(
    "api.openai.com"
    "api.anthropic.com"
    "generativelanguage.googleapis.com"
    "api.cohere.ai"
    "api.mistral.ai"
    "api.together.xyz"
    "api.replicate.com"
    "api-inference.huggingface.co"
    "api.groq.com"
    "api.perplexity.ai"
    "api.deepseek.com"
    "api.fireworks.ai"
)

# --- Known AI process signatures ---
AI_PROCESSES=(
    "ollama"
    "llama.cpp"
    "llama-server"
    "text-generation-launcher"
    "vllm"
    "localai"
    "koboldcpp"
    "lm-studio"
    "aider"
    "tabby"
)

# --- Known AI container images ---
AI_IMAGES=(
    "ollama"
    "localai"
    "vllm"
    "text-generation-inference"
    "oobabooga"
    "open-webui"
    "flowise"
    "dify"
    "litellm"
    "anythingllm"
)

# --- Resolve domains to IPs ---
declare -A IP_TO_DOMAIN
for domain in "${AI_DOMAINS[@]}"; do
    for ip in $(dig +short "$domain" A 2>/dev/null || true); do
        [[ "$ip" =~ ^[0-9]+\. ]] && IP_TO_DOMAIN["$ip"]="$domain"
    done
done

FINDINGS="[]"

add_finding() {
    local json="$1"
    FINDINGS=$(echo "$FINDINGS" | python3 -c "
import sys, json
arr = json.load(sys.stdin)
arr.append(json.loads('''$json'''))
print(json.dumps(arr))
" 2>/dev/null || echo "$FINDINGS")
}

# --- Scan 1: Network connections ---
if command -v ss &>/dev/null; then
    while IFS= read -r line; do
        for ip in "${!IP_TO_DOMAIN[@]}"; do
            if [[ "$line" == *"$ip"* ]]; then
                domain="${IP_TO_DOMAIN[$ip]}"
                add_finding "{\"detection_type\":\"network\",\"destination\":\"${ip}:443 (${domain})\",\"details\":{\"domain\":\"${domain}\"}}"
                break
            fi
        done
    done < <(ss -tnp 2>/dev/null || true)
elif command -v netstat &>/dev/null; then
    while IFS= read -r line; do
        for ip in "${!IP_TO_DOMAIN[@]}"; do
            if [[ "$line" == *"$ip"* ]]; then
                domain="${IP_TO_DOMAIN[$ip]}"
                add_finding "{\"detection_type\":\"network\",\"destination\":\"${ip}:443 (${domain})\",\"details\":{\"domain\":\"${domain}\"}}"
                break
            fi
        done
    done < <(netstat -tn 2>/dev/null || true)
fi

# --- Scan 2: Running processes ---
while IFS= read -r line; do
    line_lower=$(echo "$line" | tr '[:upper:]' '[:lower:]')
    for sig in "${AI_PROCESSES[@]}"; do
        sig_lower=$(echo "$sig" | tr '[:upper:]' '[:lower:]')
        if [[ "$line_lower" == *"$sig_lower"* ]]; then
            pid=$(echo "$line" | awk '{print $2}')
            cmd=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}')
            # Skip grep/scanner self-matches
            [[ "$cmd" == *"shadow-ai"* ]] && continue
            [[ "$cmd" == *"grep"* ]] && continue
            add_finding "{\"detection_type\":\"process\",\"process_name\":\"${sig}\",\"pid\":${pid:-0},\"command_line\":\"$(echo "$cmd" | head -c 500 | sed 's/"/\\"/g')\"}"
            break
        fi
    done
done < <(ps aux 2>/dev/null || true)

# --- Scan 3: Docker containers ---
if command -v docker &>/dev/null; then
    while IFS=$'\t' read -r cid image name cstatus; do
        image_lower=$(echo "$image" | tr '[:upper:]' '[:lower:]')
        for known in "${AI_IMAGES[@]}"; do
            known_lower=$(echo "$known" | tr '[:upper:]' '[:lower:]')
            if [[ "$image_lower" == *"$known_lower"* ]]; then
                add_finding "{\"detection_type\":\"container\",\"container_id\":\"${cid}\",\"container_image\":\"${image}\",\"process_name\":\"${name}\",\"details\":{\"status\":\"${cstatus}\"}}"
                break
            fi
        done
    done < <(docker ps --format '{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}' 2>/dev/null || true)
fi

# --- Report findings ---
COUNT=$(echo "$FINDINGS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)

if [ "$COUNT" -eq 0 ]; then
    echo "[shadow-ai-scanner] No findings on ${HOST_ID}"
    exit 0
fi

echo "[shadow-ai-scanner] Found ${COUNT} finding(s) on ${HOST_ID}, reporting to ${SNAPPER_URL}..."

PAYLOAD=$(python3 -c "
import json, sys
findings = json.loads('''$(echo "$FINDINGS")''')
print(json.dumps({'host_identifier': '${HOST_ID}', 'findings': findings}))
")

CURL_ARGS=(-s -X POST "${REPORT_ENDPOINT}" -H "Content-Type: application/json" -d "${PAYLOAD}")
if [ -n "${SNAPPER_API_KEY}" ]; then
    CURL_ARGS+=(-H "X-API-Key: ${SNAPPER_API_KEY}")
fi

RESPONSE=$(curl "${CURL_ARGS[@]}" 2>&1 || true)
echo "[shadow-ai-scanner] Response: ${RESPONSE}"
