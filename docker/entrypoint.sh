#!/bin/sh
# Runs the VPN tunnel plus its mixed proxy from environment variables, so the
# only host-facing surface is the published proxy port.
#
# Any command-line arguments bypass this wrapper: `docker run inode-cli --version`.
set -eu

if [ "$#" -gt 0 ]; then
    exec inode "$@"
fi

: "${INODE_GATEWAY:?INODE_GATEWAY is required, e.g. https://vpn.example.com:443}"
: "${INODE_USER:?INODE_USER is required}"

listen="${INODE_PROXY_LISTEN:-0.0.0.0:1080}"
set -- connect "$INODE_GATEWAY" --user "$INODE_USER" --password-stdin --proxy-listen "$listen"

[ "${INODE_INSECURE:-0}" = "1" ] && set -- "$@" --insecure
[ -n "${INODE_SERVERCERT:-}" ] && set -- "$@" --servercert "$INODE_SERVERCERT"
[ -n "${INODE_CA:-}" ] && set -- "$@" --ca "$INODE_CA"
[ -n "${INODE_MTU:-}" ] && set -- "$@" --mtu "$INODE_MTU"
[ -n "${INODE_KEEPALIVE:-}" ] && set -- "$@" --keepalive "$INODE_KEEPALIVE"
[ -n "${INODE_RECONNECT_ATTEMPTS:-}" ] && set -- "$@" --reconnect-attempts "$INODE_RECONNECT_ATTEMPTS"
[ -n "${INODE_PROXY_USER:-}" ] && set -- "$@" --proxy-user "$INODE_PROXY_USER"
[ -n "${INODE_PROXY_PASSWORD:-}" ] && set -- "$@" --proxy-password "$INODE_PROXY_PASSWORD"
for route in ${INODE_ROUTES:-}; do
    set -- "$@" --route "$route"
done
case "${INODE_GATEWAY_ROUTES:-1}" in
0 | no | false) ;;
*) set -- "$@" --gateway-routes ;;
esac

if [ -n "${INODE_PASSWORD_FILE:-}" ]; then
    exec inode "$@" < "$INODE_PASSWORD_FILE"
fi
: "${INODE_PASSWORD:?set INODE_PASSWORD_FILE (preferred) or INODE_PASSWORD}"
# /run is tmpfs; the file dies with the container and is never in argv.
umask 077
printf '%s\n' "$INODE_PASSWORD" > /run/inode-password
exec inode "$@" < /run/inode-password
