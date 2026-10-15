"""A durable on-server backup request; it never transmits data by itself."""
import json
import os
import socket

SOCKET=os.getenv('RELAY_BACKUP_SOCKET','/run/relay-backup/control.sock')

def changed(reason='settings'):
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.settimeout(3);sock.connect(SOCKET)
            sock.sendall(json.dumps({'op':'changed','reason':reason}).encode()+b'\n')
            sock.recv(4096)
    except OSError:
        # The backup worker also periodically fingerprints the important state.
        pass
