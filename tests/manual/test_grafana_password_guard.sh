#!/usr/bin/env bash
# Exercises the GRAFANA_PASSWORD guard block from setup.sh --prod
# against a matrix of inputs. Kept under tests/manual/ because it is
# not part of `make test` (shell test, not pytest).
#
# Usage: bash tests/manual/test_grafana_password_guard.sh
#
# Runs the guard's actual logic (extracted to a function) against known
# weak values and confirms each is rejected. Confirms strong values pass.

set -uo pipefail

# ── Guard under test (mirror of setup.sh block) ──────────────────────────────
check_grafana_password() {
    GRAFANA_PASSWORD="$1"
    [ -z "$GRAFANA_PASSWORD" ] && { echo "FAIL: unset"; return 1; }
    gp_lower=$(printf '%s' "$GRAFANA_PASSWORD" | tr '[:upper:]' '[:lower:]')
    case "$gp_lower" in
        admin|password|grafana|wrapsec|changeme|changeme_before_deploy|letmein|123456|qwerty|default)
            echo "FAIL: weak"
            return 1
            ;;
    esac
    if [ "${#GRAFANA_PASSWORD}" -lt 12 ]; then
        echo "FAIL: short"
        return 1
    fi
    echo "PASS"
    return 0
}

# ── Test matrix ─────────────────────────────────────────────────────────────
WEAK_VALUES=(
    "admin" "Admin" "ADMIN"
    "password" "Password"
    "changeme" "changeme_before_deploy"
    "grafana" "wrapsec"
    "letmein" "123456" "qwerty" "default"
    ""            # unset
    "short12"     # 7 chars - too short
    "elevenchars"  # 11 chars - too short
)

STRONG_VALUES=(
    "twelve_char1"                    # exactly 12
    "$(openssl rand -base64 24)"      # 32 chars random
    "MyStrongPass2026!"               # 17 chars, mixed
    "AdminButLongerAndUnique123"      # starts with "admin" but full string is not weak
)

fails=0
echo "── Weak values (should FAIL) ──"
for v in "${WEAK_VALUES[@]}"; do
    result=$(check_grafana_password "$v")
    if [[ "$result" == PASS ]]; then
        echo "  BUG: '$v' passed but should have failed"
        fails=$((fails + 1))
    else
        printf "  ok   '%s' -> %s\n" "$v" "$result"
    fi
done

echo ""
echo "── Strong values (should PASS) ──"
for v in "${STRONG_VALUES[@]}"; do
    result=$(check_grafana_password "$v")
    if [[ "$result" != PASS ]]; then
        echo "  BUG: '$v' rejected but should have passed ($result)"
        fails=$((fails + 1))
    else
        printf "  ok   '%s' -> PASS\n" "$v"
    fi
done

echo ""
if [ "$fails" -eq 0 ]; then
    echo "All cases behaved correctly."
    exit 0
else
    echo "$fails case(s) misbehaved."
    exit 1
fi
