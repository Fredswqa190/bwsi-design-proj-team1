#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
from Crypto.Hash import SHA256
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
from base64 import b64encode
from Crypto.Cipher import ChaCha20_Poly1305

def AESProtect(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    # Reads key for AES (256 bit key length)
    with open('../bootloader/secret_build_output.txt', 'rb') as f:
        AESkey = f.read(32)

    # Hash firmware file using SHA 256
    hash = SHA256.new()
    hash.update(firmware)

    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b'\00'

    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))

    # Encrypt FIRWMARE with AES-GCM 
    cipherNew = AES.new(AESkey, AES.MODE_GCM)
    output = cipherNew.encrypt(pad(firmware_and_message, AES.block_size))

    # Adds metadata and encrypted firmware to a firmware_blob
    firmware_blob = metadata + output

    # Hash firmware blob using SHA 256
    hash = SHA256.new()
    hash.update(firmware_blob)
    hash_value = hash.digest()
    print(hash_value)

    # Adds hash value and null-terminated message to end of blob
    firmware_blob = firmware_blob + hash_value + message.encode() + b'00'

    # Writes hash into secret output file 
    with open('secret_build_output.txt', 'wb') as f:
        f.write(hash_value) 
    
    # Write firmware blob to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(firmware_blob)

        # Hashes the output file
        hash2 = SHA256.new()
        hash2.update(outfile)
    
def CC20P1305Protect(outfile):
    with open('../bootloader/secret_build_output.txt', 'rb') as f:
        AESkey = f.read(32)
        Chakey = f.read(32)
    
    #with open(outfile, 'r') as infile:
    #    firmwareEncrypt1 = infile.read()
    #header = b'stuff'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    AESProtect(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
    CC20P1305Protect(outfile=args.infile)