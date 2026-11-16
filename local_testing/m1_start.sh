#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"


mkdir -p logs

SESSION="relays"

if [[ "$1" == "stop" ]]; then
    for pane in $(tmux list-panes -t "$SESSION" -F "#{pane_id}" 2>/dev/null); do
        tmux send-keys -t "$pane" C-c
    done
    sleep 2
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    echo "m1 nodes stopped."
    exit 0
fi

tmux kill-session -t "$SESSION" 2>/dev/null || true

# Capture sudo password once so all 3 panes start immediately without separate prompts
read -r -s -p "[sudo] password for $(whoami): " SUDO_PASS
echo ""

# Pane 0: Relay 1 (port 7001)
tmux new-session -d -s "$SESSION" -n "mac2" \
    "echo '$SUDO_PASS' | sudo -S QUILL_LOG_LEVEL=debug ../cmake-build-release/comyc -r relay -p 7001 -b 192.168.1.205 --bootstrap-port 6969 -c -l ./logs/relay-1_logs.txt; read"

# Pane 1: Relay 2 (port 7002)
tmux split-window -h -t "$SESSION:0" \
    "echo '$SUDO_PASS' | sudo -S QUILL_LOG_LEVEL=debug ../cmake-build-release/comyc -r relay -p 7002 -b 192.168.1.205 --bootstrap-port 6969 -c -l ./logs/relay-2_logs.txt; read"

# Pane 2: Exit node (port 8001)
tmux split-window -v -t "$SESSION:0.0" \
    "echo '$SUDO_PASS' | sudo -S QUILL_LOG_LEVEL=debug ../cmake-build-release/comyc -r exit -p 8001 -l ./logs/exit_logs.txt -c; read"

unset SUDO_PASS

tmux select-layout -t "$SESSION:0" tiled
tmux attach-session -t "$SESSION"