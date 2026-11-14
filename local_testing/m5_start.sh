#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

cmake --build ../build
mkdir -p logs

SESSION="bootstrap_client"

if [[ "$1" == "stop" ]]; then
    for pane in $(tmux list-panes -t "$SESSION" -F "#{pane_id}" 2>/dev/null); do
        tmux send-keys -t "$pane" C-c
    done
    sleep 2
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    echo "m5 nodes stopped."
    exit 0
fi

tmux kill-session -t "$SESSION" 2>/dev/null || true

read -r -s -p "[sudo] password for $(whoami): " SUDO_PASS
echo ""

tmux new-session -d -s "$SESSION" -n "mac1" \
    "echo '$SUDO_PASS' | sudo -S QUILL_LOG_LEVEL=debug ../build/node -r relay -p 6969 -c -B -l ./logs/bootstrap_log.txt; read"

sleep 1
if ! tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "Error: Bootstrap session failed to start."
    exit 1
fi

echo "bootstrap node is running in tmux session '$SESSION'."

while true; do
    read -r -p "start client? (y/n): " yn
    case "$yn" in
        [Yy]* )
            tmux split-window -h -t "$SESSION:0" \
                "echo '$SUDO_PASS' | sudo -S QUILL_LOG_LEVEL=debug ../build/node -r client-relay -b 127.0.0.1 --bootstrap-port 6969 -c --exit-ip 192.168.0.100 --exit-port 8001 -l ./logs/client_logs.txt -j; read"
            unset SUDO_PASS
            tmux attach-session -t "$SESSION"
            break
            ;;
        [Nn]* )
            unset SUDO_PASS
            echo "Bootstrap is running in the background. run 'tmux attach -t $SESSION' to view."
            exit 0
            ;;
        * )
            echo "y/n:"
            ;;
    esac
done