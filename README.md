# netsec-chat
A secure relay-based chat system.

You'll need Python 3.8 or above to run this.

First, setup the keys by running `python3 keygen.py`.

Afterwards, you can run the program using each of the following commands in separate terminal windows:
```bash
python3 relay.py
```
```bash
python3 client.py
```
```bash
python3 client.py
```

The first `client.py` will run as Bob, waiting and listening for Alice to start a session. The second `client.py` will run as Alice. The clients are configured to register with the relay and perform all the steps necessary for creating a secure chat session automatically upon start-up.

Alternatively, if `tmux` and `bash` are installed on your unix system, you may use the provided bash script `run-chat.sh` to initiate all the start-up processes automatically.

```bash
chmod 744 run-chat.sh
./run-chat.sh
```
