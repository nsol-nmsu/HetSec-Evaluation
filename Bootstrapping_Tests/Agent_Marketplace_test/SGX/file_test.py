import os
import time
import socket
import queue
import asyncio
import ssl
from attest_util import verify_peer_cert_via_qve
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding



with open("bootApp.py", 'r') as file:
    response = file.read()
    print(len(response))


