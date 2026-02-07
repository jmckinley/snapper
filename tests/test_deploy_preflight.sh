#!/usr/bin/env bash
# Test harness for deploy.sh prerequisite detection logic
# Runs on macOS/Linux — no root required, no real installs
#
# Extracts the detection section from deploy.sh and exercises it
# with controlled PATH to simulate missing/present commands.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY="$SCRIPT_DIR/deploy.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS + 1)); TOTAL=$((TOTAL + 1)); echo -e "${GREEN}  PASS${NC} $1"; }
fail() { FAIL=$((FAIL + 1)); TOTAL=$((TOTAL + 1)); echo -e "${RED}  FAIL${NC} $1"; }

# ─── Setup: create a temp dir with fake binaries ─────────────────────────

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

FAKE_BIN="$WORK/bin"
mkdir -p "$FAKE_BIN"

# Create fake commands that just succeed
for cmd in git curl openssl caddy ufw; do
    printf '#!/bin/sh\nexit 0\n' > "$FAKE_BIN/$cmd"
    chmod +x "$FAKE_BIN/$cmd"
done

# Fake docker that also handles "docker compose version"
cat > "$FAKE_BIN/docker" <<'DOCKER'
#!/bin/sh
if [ "$1" = "compose" ] && [ "$2" = "version" ]; then
    echo "Docker Compose version v2.29.0"
    exit 0
fi
exit 0
DOCKER
chmod +x "$FAKE_BIN/docker"

# Fake awk for check_ram (returns high RAM so no warning)
cat > "$FAKE_BIN/awk" <<'AWK'
#!/bin/sh
echo "16000000"
AWK
chmod +x "$FAKE_BIN/awk"

REAL_BASH=$(which bash)

# ─── Build the test script once ──────────────────────────────────────────

build_test_script() {
    local os_id="$1"  # ubuntu or alpine

    local os_release="$WORK/os-release-${os_id}"
    if [[ "$os_id" == "ubuntu" ]]; then
        printf 'ID=ubuntu\nVERSION_CODENAME=noble\nID_LIKE=debian\n' > "$os_release"
    else
        printf 'ID=alpine\nID_LIKE=\n' > "$os_release"
    fi

    cat > "$WORK/test_preflight_${os_id}.sh" <<ENDSCRIPT
#!/bin/bash
# Stub colors and logging
log()  { echo "[snapper] \$1"; }
ok()   { echo "[  ok  ] \$1"; }
warn() { echo "[ warn ] \$1"; }
err()  { echo "[error ] \$1" >&2; }

# Stub install functions — just print what was called
install_basic_tools() { echo "CALLED: install_basic_tools \$*"; }
install_docker()      { echo "CALLED: install_docker"; }
install_caddy()       { echo "CALLED: install_caddy"; }

# Stub check_os
check_os() {
    IS_UBUNTU_DEBIAN=no
    . "$os_release"
    if [ "\$ID" = "ubuntu" ] || [ "\$ID" = "debian" ]; then
        IS_UBUNTU_DEBIAN=yes
    fi
}

check_ram() { :; }

# ── Detection logic (mirrors deploy.sh) ──
check_os
check_ram

MISSING_BASIC=()
for cmd in git curl openssl; do
    if ! command -v "\$cmd" >/dev/null 2>&1; then
        MISSING_BASIC+=("\$cmd")
    fi
done

NEED_DOCKER=false
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    NEED_DOCKER=true
fi

NEED_CADDY=false
if ! command -v caddy >/dev/null 2>&1; then
    NEED_CADDY=true
fi

NEED_UFW=false
if ! command -v ufw >/dev/null 2>&1; then
    NEED_UFW=true
fi

if [ \${#MISSING_BASIC[@]} -eq 0 ] && [ "\$NEED_DOCKER" = "false" ] && [ "\$NEED_CADDY" = "false" ] && [ "\$NEED_UFW" = "false" ]; then
    ok "All prerequisites found"
else
    # Required prerequisites
    if [ \${#MISSING_BASIC[@]} -gt 0 ] || [ "\$NEED_DOCKER" = "true" ] || [ "\$NEED_CADDY" = "true" ]; then
        echo ""
        warn "Missing required prerequisites:"
        if [ \${#MISSING_BASIC[@]} -gt 0 ]; then
            warn "  - Basic tools: \${MISSING_BASIC[*]}"
        fi
        if [ "\$NEED_DOCKER" = "true" ]; then
            warn "  - Docker Engine + Compose plugin"
        fi
        if [ "\$NEED_CADDY" = "true" ]; then
            warn "  - Caddy web server"
        fi
        echo ""

        if [ "\$IS_UBUNTU_DEBIAN" = "yes" ]; then
            echo "This script can install them automatically from official repositories."
            read -r -p "Install missing prerequisites? [y/N] " INSTALL_CONFIRM
            echo ""

            if [ "\$INSTALL_CONFIRM" != "y" ] && [ "\$INSTALL_CONFIRM" != "Y" ]; then
                err "Cannot continue without prerequisites. Install them manually and re-run."
                exit 1
            fi

            if [ \${#MISSING_BASIC[@]} -gt 0 ]; then
                install_basic_tools "\${MISSING_BASIC[@]}"
            fi
            if [ "\$NEED_DOCKER" = "true" ]; then
                install_docker
            fi
            if [ "\$NEED_CADDY" = "true" ]; then
                install_caddy
            fi

            ok "All required prerequisites installed and verified"
        else
            err "Automatic install is only supported on Ubuntu/Debian."
            err "Please install the missing tools manually:"
            err "  Docker: https://docs.docker.com/engine/install/"
            err "  Caddy:  https://caddyserver.com/docs/install"
            exit 1
        fi
    else
        ok "All required prerequisites found"
    fi

    # Optional: UFW firewall
    if [ "\$NEED_UFW" = "true" ]; then
        echo ""
        warn "UFW firewall is not installed."
        warn "It's recommended for VPS deployments but not strictly required"
        warn "(you may have iptables, nftables, or a provider-level firewall)."

        if [ "\$IS_UBUNTU_DEBIAN" = "yes" ]; then
            read -r -p "Install UFW? [y/N] " UFW_CONFIRM
            echo ""
            if [ "\$UFW_CONFIRM" = "y" ] || [ "\$UFW_CONFIRM" = "Y" ]; then
                log "Installing UFW..."
                ok "UFW installed"
            else
                warn "Skipping UFW — make sure you have another firewall in place."
            fi
        else
            warn "Install a firewall manually if your provider doesn't offer one."
        fi
    fi
fi

echo "PREFLIGHT_DONE"
ENDSCRIPT
    chmod +x "$WORK/test_preflight_${os_id}.sh"
}

build_test_script ubuntu
build_test_script alpine

# ─── Helper: run a test case ─────────────────────────────────────────────

run_preflight() {
    local description="$1"
    local path="$2"
    local stdin_file="$3"       # file with stdin content
    local expect_exit="$4"      # expected exit code
    local expect_pattern="$5"   # grep pattern in combined output
    local os="${6:-ubuntu}"     # OS to simulate

    local output exit_code=0
    output=$("$REAL_BASH" "$WORK/test_preflight_${os}.sh" < "$stdin_file" 2>&1) || exit_code=$?

    # Check exit code
    if [[ "$exit_code" -ne "$expect_exit" ]]; then
        fail "$description (expected exit $expect_exit, got $exit_code)"
        echo "    OUTPUT: $(echo "$output" | head -3)"
        return
    fi

    # Check pattern if specified
    if [[ -n "$expect_pattern" ]]; then
        if echo "$output" | grep -qF "$expect_pattern"; then
            pass "$description"
        else
            fail "$description (pattern '$expect_pattern' not found)"
            echo "    OUTPUT: $(echo "$output" | head -5)"
        fi
    else
        pass "$description"
    fi
}

# ─── Create PATH variants and stdin files ────────────────────────────────

# Stdin files
printf 'y\n'   > "$WORK/stdin_y"
printf 'n\n'   > "$WORK/stdin_n"
printf '\n'    > "$WORK/stdin_empty"
printf 'y\nn\n' > "$WORK/stdin_y_n"
printf 'y\ny\n' > "$WORK/stdin_y_y"

# PATH: everything present
ALL_PRESENT="$FAKE_BIN"

# PATH: no git
NO_GIT="$WORK/no_git"
mkdir -p "$NO_GIT"
for cmd in curl openssl caddy ufw docker awk; do
    ln -sf "$FAKE_BIN/$cmd" "$NO_GIT/$cmd"
done

# PATH: no docker
NO_DOCKER="$WORK/no_docker"
mkdir -p "$NO_DOCKER"
for cmd in git curl openssl caddy ufw awk; do
    ln -sf "$FAKE_BIN/$cmd" "$NO_DOCKER/$cmd"
done

# PATH: no caddy
NO_CADDY="$WORK/no_caddy"
mkdir -p "$NO_CADDY"
for cmd in git curl openssl docker ufw awk; do
    ln -sf "$FAKE_BIN/$cmd" "$NO_CADDY/$cmd"
done

# PATH: no ufw only
NO_UFW="$WORK/no_ufw"
mkdir -p "$NO_UFW"
for cmd in git curl openssl caddy docker awk; do
    ln -sf "$FAKE_BIN/$cmd" "$NO_UFW/$cmd"
done

# PATH: no docker, no caddy, no ufw
MINIMAL="$WORK/minimal"
mkdir -p "$MINIMAL"
for cmd in git curl openssl awk; do
    ln -sf "$FAKE_BIN/$cmd" "$MINIMAL/$cmd"
done

# PATH: nothing except awk
EMPTY="$WORK/empty_path"
mkdir -p "$EMPTY"
ln -sf "$FAKE_BIN/awk" "$EMPTY/awk"

# PATH: docker present but compose broken
BROKEN_COMPOSE="$WORK/broken_compose"
mkdir -p "$BROKEN_COMPOSE"
for cmd in git curl openssl caddy ufw awk; do
    ln -sf "$FAKE_BIN/$cmd" "$BROKEN_COMPOSE/$cmd"
done
cat > "$BROKEN_COMPOSE/docker" <<'DOCKER'
#!/bin/sh
if [ "$1" = "compose" ]; then
    exit 1
fi
exit 0
DOCKER
chmod +x "$BROKEN_COMPOSE/docker"

# Override PATH for all run_preflight calls
_orig_run_preflight=$(declare -f run_preflight)
eval "orig_run_preflight() ${_orig_run_preflight#*\)}"

run_preflight() {
    local description="$1"
    local path="$2"
    local stdin_file="$3"
    local expect_exit="$4"
    local expect_pattern="$5"
    local os="${6:-ubuntu}"

    local output exit_code=0
    output=$(PATH="$path" "$REAL_BASH" "$WORK/test_preflight_${os}.sh" < "$stdin_file" 2>&1) || exit_code=$?

    if [[ "$exit_code" -ne "$expect_exit" ]]; then
        fail "$description (expected exit $expect_exit, got $exit_code)"
        echo "    OUTPUT: $(echo "$output" | head -3)"
        return
    fi

    if [[ -n "$expect_pattern" ]]; then
        if echo "$output" | grep -qF "$expect_pattern"; then
            pass "$description"
        else
            fail "$description (pattern '$expect_pattern' not found)"
            echo "    OUTPUT: $(echo "$output" | head -5)"
        fi
    else
        pass "$description"
    fi
}

# ─── Tests ───────────────────────────────────────────────────────────────

echo ""
echo "==========================================================="
echo "  deploy.sh preflight detection tests"
echo "==========================================================="
echo ""

# ── 1. Syntax check ─────────────────────────────────────────────────────
echo "-- Syntax --"
if bash -n "$DEPLOY" 2>&1; then
    pass "bash -n deploy.sh (syntax valid)"
else
    fail "bash -n deploy.sh (syntax errors)"
fi

# ── 2. Shellcheck ────────────────────────────────────────────────────────
if command -v shellcheck &>/dev/null; then
    if shellcheck "$DEPLOY" 2>&1; then
        pass "shellcheck deploy.sh (no warnings)"
    else
        fail "shellcheck deploy.sh (has warnings)"
    fi
fi

# ── 3. Happy path: everything present ────────────────────────────────────
echo ""
echo "-- Happy path --"
run_preflight \
    "All tools present -> no prompt, exits 0" \
    "$ALL_PRESENT" "$WORK/stdin_empty" 0 "All prerequisites found"

# ── 4. Missing basic tools ───────────────────────────────────────────────
echo ""
echo "-- Missing basic tools --"

run_preflight \
    "Missing git detected in output" \
    "$NO_GIT" "$WORK/stdin_y" 0 "Basic tools: git"

run_preflight \
    "Missing git + decline -> exit 1" \
    "$NO_GIT" "$WORK/stdin_n" 1 "Cannot continue"

run_preflight \
    "Missing git + empty input (default N) -> exit 1" \
    "$NO_GIT" "$WORK/stdin_empty" 1 "Cannot continue"

# ── 5. Missing Docker ───────────────────────────────────────────────────
echo ""
echo "-- Missing Docker --"

run_preflight \
    "Missing docker detected" \
    "$NO_DOCKER" "$WORK/stdin_y" 0 "Docker Engine"

run_preflight \
    "Missing docker + accept -> calls install_docker" \
    "$NO_DOCKER" "$WORK/stdin_y" 0 "CALLED: install_docker"

# ── 6. Missing Caddy ────────────────────────────────────────────────────
echo ""
echo "-- Missing Caddy --"

run_preflight \
    "Missing caddy detected" \
    "$NO_CADDY" "$WORK/stdin_y" 0 "Caddy web server"

run_preflight \
    "Missing caddy + accept -> calls install_caddy" \
    "$NO_CADDY" "$WORK/stdin_y" 0 "CALLED: install_caddy"

# ── 7. Missing UFW only (optional) ──────────────────────────────────────
echo ""
echo "-- Missing UFW (optional) --"

run_preflight \
    "Only UFW missing -> UFW prompt shown" \
    "$NO_UFW" "$WORK/stdin_n" 0 "UFW firewall is not installed"

run_preflight \
    "Only UFW missing + decline -> exits 0 (not blocking)" \
    "$NO_UFW" "$WORK/stdin_n" 0 "Skipping UFW"

run_preflight \
    "Only UFW missing + accept -> installs UFW" \
    "$NO_UFW" "$WORK/stdin_y" 0 "UFW installed"

run_preflight \
    "Only UFW missing -> required prereqs reported as found" \
    "$NO_UFW" "$WORK/stdin_n" 0 "All required prerequisites found"

# ── 8. Multiple missing (Docker + Caddy + UFW) ──────────────────────────
echo ""
echo "-- Multiple missing --"

run_preflight \
    "Docker+Caddy+UFW missing, accept required, decline UFW -> exit 0" \
    "$MINIMAL" "$WORK/stdin_y_n" 0 "PREFLIGHT_DONE"

run_preflight \
    "Docker+Caddy+UFW missing, decline required -> exit 1" \
    "$MINIMAL" "$WORK/stdin_n" 1 "Cannot continue"

# ── 9. Non-Ubuntu OS ────────────────────────────────────────────────────
echo ""
echo "-- Non-Ubuntu/Debian --"

run_preflight \
    "Missing docker on Alpine -> manual install message, exit 1" \
    "$NO_DOCKER" "$WORK/stdin_empty" 1 "only supported on Ubuntu/Debian" alpine

run_preflight \
    "Only UFW missing on Alpine -> warns, doesn't block" \
    "$NO_UFW" "$WORK/stdin_empty" 0 "Install a firewall manually" alpine

# ── 10. Missing everything ──────────────────────────────────────────────
echo ""
echo "-- Missing everything --"

run_preflight \
    "Nothing installed + accept -> calls all installers" \
    "$EMPTY" "$WORK/stdin_y_y" 0 "CALLED: install_basic_tools"

# ── 11. Docker without Compose ──────────────────────────────────────────
echo ""
echo "-- Docker without Compose --"

run_preflight \
    "Docker present but compose broken -> detected as missing" \
    "$BROKEN_COMPOSE" "$WORK/stdin_y" 0 "Docker Engine"

# ─── Summary ─────────────────────────────────────────────────────────────
echo ""
echo "==========================================================="
if [[ $FAIL -eq 0 ]]; then
    echo -e "  ${GREEN}All $TOTAL tests passed${NC}"
else
    echo -e "  ${RED}$FAIL of $TOTAL tests failed${NC}"
fi
echo "==========================================================="
echo ""

exit $FAIL
