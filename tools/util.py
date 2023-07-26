#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

import os
import socket
from Crypto.PublicKey import ECC
from chacha20poly1305 import ChaCha20Poly1305

UART0_PATH = "/embsec/UART0"
UART1_PATH = "/embsec/UART1"
UART2_PATH = "/embsec/UART2"

class DomainSocketSerial:
    def __init__(self, ser_socket: socket.socket):
        self.ser_socket = ser_socket
    
    def read(self, length: int) -> bytes:
        if length < 1:
            raise ValueError("Read length must be at least 1 byte")
        
        return self.ser_socket.recv(length)
    
    def readline(self) -> bytes:
        line = b""

        c = self.ser_socket.recv(1)
        while c != b"\n":
            line += c
            c = self.ser_socket.recv(1)
        
        line += b'\n'
        return line

    def write(self, data: bytes):
        self.ser_socket.send(data)

    def close(self):
        self.ser_socket.close()
        del self

def print_hex(data):
    hex_string = ' '.join(format(byte, '02x') for byte in data)
    print(hex_string)

def eccKeygen(): # Not sure if we should touch this rn
    key = ECC.generate(curve='P-256')
    f = open('secret_build_output.txt','a')
    f.write(key.export_key(format='PEM'))
    f.write("\n")
    f.write(key.public_key().export_key(format='PEM'))

def chacha20poly1305Gen():
    key = os.urandom(32)
    cip = ChaCha20Poly1305(key)
    with open('firmware/gcc/main.bin', 'rb') as fp:
        firmware = fp.read()
    nonce = os.urandom(12)
    ciphertext = cip.encrypt(nonce, firmware)
    return ciphertext
    # Unfinished- write ciphertext