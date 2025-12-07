# !/bin/bash

if [[ ! -e ./relay_private_key.pem ]]; then
    python3 keygen.py
fi

tmux new -d -s chat "python3 relay.py"   
tmux split-window -h -t chat.0 "python3 client.py bob" 
tmux split-window -h -t chat.0 "python3 client.py alice" 
tmux attach-session -t chat
