# netsec-chat
A secure relay-based chat system.

First, setup the keys by running `python3 keygen.py`.
Afterwards, you can run the program using the following commands in separate windows:
```
python3 relay.py
python3 client.py bob
python3 client.py alice
```
Alternatively, if `tmux` is installed on your system, you can use the provided bash script to run the commands (including key setup) automatically.