#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from Crypto.Cipher import ChaCha20_Poly1305
import util

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()
        print('firmware:' +str(len(firmware)))
        fwSize=len(firmware)
        
    # Reads keys, IV, nonce, etc for AES and CHA 
    with open('secret_build_output.txt', 'rb') as f:
        aesKey = f.read(16)
        aesiv = f.read(16)
        chaKey = f.read(32)
        nonce = f.read(12)
        associatedData  = f.read(26)

    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))
    print(metadata)

    #gets firmware and firmware size
    firmwareAndSize = fwSize.to_bytes(16, "little")+ firmware

    # Encrypt FIRWMARE with AES-GCM 
    cipherNew = AES.new(aesKey, AES.MODE_CBC, iv=aesiv)
    AESoutput= cipherNew.encrypt(pad(firmwareAndSize, AES.block_size))
    # Adds AES to firmware blob 
    firmware_blob = AESoutput

    # Hash firmware blob (AES) using SHA 256
    hash = SHA256.new()
    hash.update(firmware_blob)
    hash_value = hash.digest()
    print(hash_value)

     # Writes hash into secret output file 
    with open('secret_build_output.txt', 'wb') as f:
        f.write(hash_value) 
    
    #creates cipher for ChaCha
    cipher = ChaCha20_Poly1305.new(key=chaKey, nonce = nonce)

    # protect associated data
    cipher.update(associatedData)

    #adds aes output and hash to be chacha'd
    AESoutput_hash = AESoutput + hash.digest()
    AESlen=len(AESoutput)

    print('hash digest: ' +str(len(hash.digest())))
    print('aes: ' +str(len(AESoutput)))
    print('aes&Hash: ' +str(len(AESoutput_hash)))

    # encrypts already encrypted AES data from before with chacha 
    ciphertext, tag = cipher.encrypt_and_digest(AESoutput_hash)
    
    #generates size of ciphertext
    cTextSize = len(ciphertext)

    # Constructs the firmware blob: metadata [already stored] + encrypted firmware + iv + hash of AES and metadata
    firmware_blob = cTextSize.to_bytes(16, 'little') + AESlen.to_bytes(16, 'little')+ ciphertext + tag + hash.digest()

    print('ciphertext: '+str(cTextSize))
    print('tag: ' + str(len(tag)))
    print('hash digest: ' + str(len(hash.digest())))

    #set length equal to firmware length    
    length = len(firmware_blob)

    # Adds null-terminated message to indicate ending of blob
    firmware_blob1 = firmware_blob + message.encode() + b'00'

    print('message: ' + str(len(message.encode())))
    print('firmware blob: '+str(len(firmware_blob)))

    #adding size
    #structure: metadata, total size, ctextsize, aessize, encrypted(aes output[actualFirmware], hash), tag, hash, message, 0
    firmware_blob=metadata+length.to_bytes(16, 'little')+firmware_blob1
    print('metadata: ' + str(len(metadata)))
    
    print(len(firmware_blob))


    # Write firmware blob to outfile
    with open(outfile, 'wb') as outfile:
        outfile.write(firmware_blob)

"""def lengthCheck(firmware_blob):
        length = len(firmware_blob)
        return length"""

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    #Encrypts firmware using AEs, then hashes using SHA, then encrypts again using ChaCha20-Poly1304
    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)