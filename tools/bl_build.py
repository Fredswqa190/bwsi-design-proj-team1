#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import argparse
import os
import pathlib
import shutil
import subprocess
from Crypto.PublicKey import ECC
import util


REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")




def copy_initial_firmware(binary_path: str):
    # Copy the initial firmware binary to the bootloader build directory

    os.chdir(os.path.join(REPO_ROOT, "tools"))
    shutil.copy(binary_path, os.path.join(BOOTLOADER_DIR, "src/firmware.bin"))


def make_bootloader() -> bool:
    # Build the bootloader from source.

    os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")
    #changed to only AES key; no ECC key gen -via
    AESkey = os.urandom(32)
    print(AESkey)

    #chacha slide generation happening here Luniva
    ChaKey = os.urandom(32) 

    # Writes keys into secret_build_output.txt
    with open("secret_build_output.txt", "wt") as f:
        f.write('\n')
        f.write(str(AESkey))
        f.write('\n')
        f.write(str(ChaKey))
        
    # Writes keys into header file secrets.h as hex
    with open("../bootloader/src/secrets.h", "wt") as f:
        f.write("#ifndef SECRETS_H\n")
        f.write("#define SECRETS_H\n")
        setup = 'const uint8_t AES_KEY[32] = '
        f.write(setup)
        list = util.print_hex(AESkey)
        print('{0x'+str(list)+"};")
        f.write('{0x'+str(list))
        f.write("};\n")
        setup = 'const uint8_t CHA_KEY[32] = '
        f.write(setup)
        list = util.print_hex(ChaKey)
        print('{0x'+str(list)+"};")
        f.write('{0x'+str(list))
        f.write("};\n")
        f.write("#endif")
        
    # Return True if make returned 0, otherwise return False.
    return status == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bootloader Build Tool")
    parser.add_argument(
        "--initial-firmware",
        help="Path to the the firmware binary.",
        default=os.path.join(REPO_ROOT, "firmware/gcc/main.bin"),
    )
    args = parser.parse_args()
    firmware_path = os.path.abspath(pathlib.Path(args.initial_firmware))

    if not os.path.isfile(firmware_path):
        raise FileNotFoundError(
            f'ERROR: {firmware_path} does not exist or is not a file. You may have to call "make" in the firmware directory.'
        )

    copy_initial_firmware(firmware_path)
    make_bootloader()
