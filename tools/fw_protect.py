#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random


def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    with open('secret_build_output.txt', 'rb') as f:
        key = f.read()

    #Seed AES Initialization Vector
    seed=("AESIV") 
    random.seed(seed)
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))

    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b'\00'

    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))

    # Append firmware and message to metadata
    firmware_blob = metadata + firmware_and_message

    # Encrypt firmware blob with AES-GCM
    cipherNew = AES.new(key, AES.MODE_GCM)
    output = cipherNew.encrypt(pad(firmware_blob, AES.block_size))
    firmware_blob = iv + output + cipherNew.digest()

    # Write firmware blob to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(firmware_blob)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
