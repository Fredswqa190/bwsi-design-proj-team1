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
    output = cipherNew.encrypt(pad(firmware, AES.block_size))

    # Adds metadata, encrypted firmware, and iv to a firmware_blob
    firmware_blob = metadata + output + iv

    # Hash firmware blob using SHA 256
    hash = SHA256.new()
    hash.update(firmware_blob)
    hash_value = hash.digest()

    # Adds hash value and null-terminated message to end of blob
    firmware_blob = firmware_blob + hash_value + message.encode() + b'00'

     # Writes hash into secret output file 
    with open('secret_build_output.txt', 'wb') as f:
        f.write(hash_value) 
    
    # Write firmware blob to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(firmware_blob)

def ChaChaslide(){
    #read chaKey and polyKey from secret file 
    with open(secret_build_output, 'rb') as f:
        ignore = f.read(32)
        chaKey = f.read(32)
        # polyKey = f.read(16)
        # after this is the hash that was created above, that gets ignored as well
        #personal note polyKey is not nonce, idk if i need it yet
        #apparently "The library handles the derivation of the 128-bit Poly1305 secret key internally."
    
    #import firmware file from above 
    with open(outfile, 'rb') as f:
        firmware = fp.read()
    
    #nonce generation
    nonce = get_random_bytes(12)
    
    #associated data (usesd for authentication)
    associatedData = b"peepeepoopoodontchangethis" 

    #creates cipher
    cipher = ChaCha20_Poly1305.new(chaKey, nonce = nonce)

    #protect associated data
    cipher.update(associatedData)

    #encrypts data
    ciphertext, tag = cipher.encrypt_and_digest(firmware, associatedData)

    #put together the encrypted data in order to transmit
    encrypted = ciphertext + tag


}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)