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

    # Reads keys for AES and CHA 
    with open('secret_build_output.txt', 'rb') as f:
        aesKey = f.read(32)
        aesiv = f.read(12)
        chaKey = f.read(32)
        nonce = f.read(12)

    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))

    # Encrypt FIRWMARE with AES-GCM 
    cipherNew = AES.new(aesKey, AES.MODE_GCM, nonce=aesiv)
    AESoutput = cipherNew.encrypt(pad(firmware, AES.block_size))

    # Adds metadata and AES to firmware blob 
    firmware_blob = metadata + AESoutput

    # Hash firmware blob (metadata and AES) using SHA 256
    hash = SHA256.new()
    hash.update(firmware_blob)
    hash_value = hash.digest()
    print(hash_value)

     # Writes hash into secret output file 
    with open('secret_build_output.txt', 'wb') as f:
        f.write(hash_value) 
    
    # associated data created (used for authentication)
    associatedData = b"peepeepoopoodontchangethis" 

    #creates cipher for ChaCha
    cipher = ChaCha20_Poly1305.new(key=chaKey, nonce = nonce)

    # protect associated data
    cipher.update(associatedData)

    #adds aes output and hash to be chacha'd
    AESoutput_hash = AESoutput + hash.digest()

    # encrypts already encrypted AES data from before with chacha 
    ciphertext, tag = cipher.encrypt_and_digest(AESoutput_hash)

    # put together the encrypted data in order to transmit
    encrypted = ciphertext + tag
    
    # Constructs the firmware blob: metadata [already stored] + encrypted firmware + iv + hash of AES and metadata
    firmware_blob = metadata + encrypted + hash.digest()

    # Adds null-terminated message to indicate ending of blob
    firmware_blob = firmware_blob + message.encode() + b'00'

    # Write firmware blob to outfile
    with open(outfile, 'wb') as outfile:
        outfile.write(firmware_blob)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)