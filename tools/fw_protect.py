#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import random
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    # Reads key for AES (should be read in bytes according to iv)
    with open('secret_build_output.txt', 'rb') as f:
        key = f.read(32)

    # Generate AES Initialization Vector
    iv = os.urandom(12)

    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))

    # Encrypt FIRWMARE with AES-GCM 
    cipherNew = AES.new(key, AES.MODE_GCM, iv=iv)
    AESoutput = cipherNew.encrypt(pad(firmware, AES.block_size))

    # Adds metadata to firmware blob (this was supposed to hash AES too)
    firmware_blob = metadata + AESoutput

    # Hash firmware blob using SHA 256
    hash = SHA256.new()
    hash.update(firmware_blob)
    hash_value = hash.digest()

     # Writes hash into secret output file 
    with open('secret_build_output.txt', 'wb') as f:
        f.write(hash_value) 

    #read chaKey and polyKey from secret file 
    with open(secret_build_output, 'rb') as f:
        ignore = f.read(32)
        chaKey = f.read(32)
    
    #nonce generation
    nonce = get_random_bytes(12)
    
    #associated data (used for authentication)
    associatedData = b"peepeepoopoodontchangethis" 

    #creates cipher
    cipher = ChaCha20_Poly1305.new(chaKey, nonce = nonce)

    #protect associated data
    cipher.update(associatedData)

    #encrypts already encrypted AES data from before with chacha 
    ciphertext, tag = cipher.encrypt_and_digest(AESoutput, associatedData)

    #put together the encrypted data in order to transmit
    encrypted = ciphertext + tag
    
    # Constructs the firmware blob: metadata [already stored] + encrypted firmware + iv + hash
    firmware_blob = firmware_blob + encrypted + iv + hash

    # Adds null-terminated message to indicate ending
    firmware_blob = firmware_blob + message.encode() + b'00'

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