# Grafana bootstrap-credential guard.
#
# Sourced by setup.sh and by tests/integration/test_grafana_password_guard.py.
# Grafana's default admin/admin is indexed by every internet scanner;
# NIST SP 800-63B (Digital Identity Guidelines) mandates rejecting commonly-
# used passwords and enforces a minimum length. The denylist below is a
# subset of the top passwords observed in credential-stuffing corpora that
# specifically apply to admin bootstrap flows (default vendor creds and the
# eternally-popular "changeme" and "admin" variants).
#
# Exit codes:
#   0 - password is acceptable
#   1 - password is unset, empty, on the denylist, or shorter than 12 chars
#
# On failure, writes a one-line reason to stderr. On success, silent.

check_grafana_password() {
    local pw="${1-}"
    local pw_lower

    if [ -z "$pw" ]; then
        echo "GRAFANA_PASSWORD is unset or empty" >&2
        return 1
    fi

    pw_lower=$(printf '%s' "$pw" | tr '[:upper:]' '[:lower:]')
    case "$pw_lower" in
        admin|password|grafana|wrapsec|changeme|changeme_before_deploy|letmein|123456|qwerty|default)
            echo "GRAFANA_PASSWORD is a well-known weak value ('$pw'). Regenerate: openssl rand -base64 24" >&2
            return 1
            ;;
    esac

    if [ "${#pw}" -lt 12 ]; then
        echo "GRAFANA_PASSWORD must be at least 12 characters. Regenerate: openssl rand -base64 24" >&2
        return 1
    fi

    return 0
}
