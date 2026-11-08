#!/bin/bash
set -e

if [ ! -c /dev/net/tun ]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 || true
    chmod 666 /dev/net/tun || true
fi

ROLE="client-relay"
for arg in "$@"; do
    case $arg in
        --role=*|-r=*)
            ROLE="${arg#*=}"
            ;;
        exit|client|relay)
            ROLE="$arg"
            ;;
    esac
done

# exit
if [[ "$*" == *"--role exit"* ]] || [[ "$*" == *"-r exit"* ]] || [ "$ROLE" == "exit" ]; then
    echo "[Entrypoint] Configuring NAT masquerading for Exit node..."
    # enable ipv4 forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    # find default interface
    PRIMARY_IFACE=$(ip route show default | awk '{print $5}' | head -n1)
    if [ -n "$PRIMARY_IFACE" ]; then
        iptables -t nat -C POSTROUTING -o "$PRIMARY_IFACE" -j MASQUERADE 2>/dev/null || \
            iptables -t nat -A POSTROUTING -o "$PRIMARY_IFACE" -j MASQUERADE
        iptables -C FORWARD -o "$PRIMARY_IFACE" -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -o "$PRIMARY_IFACE" -j ACCEPT
        iptables -C FORWARD -i "$PRIMARY_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -i "$PRIMARY_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
        echo "[Entrypoint] NAT masquerading configured on $PRIMARY_IFACE."
    fi
fi

# execute the given commadn
exec "$@"
