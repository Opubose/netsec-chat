#!/bin/bash

tmux kill-session -t chat 2>/dev/null
rm -f .chat.lock

if [[ ! -e ./relay_private_key.pem ]]; then
    python3 keygen.py
fi

tmux new-session -d -s netsec-chat -n session "python3 relay.py"

tmux move-window -t netsec-chat:1 2>/dev/null || true

tmux split-window -v -t netsec-chat:session "sleep 2; python3 client.py"

tmux split-window -h -t netsec-chat:session "sleep 1; python3 client.py"

tmux select-pane -t netsec-chat:session -L

tmux attach-session -t netsec-chat
