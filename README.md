# bwsi-design-proj-team1

# reading is hard so dont make me do this.

# README

## Running the insecure example

1. Build the firmware by navigating to `firmware/firmware`, and running `make`.
2. Build the bootloader by navigating to `tools`, and running `python bl_build.py`
2. Run the bootloader by navigating to `tools`, and running `python bl_emulate.py`

## Troubleshooting

Ensure that BearSSL is compiled for the stellaris: `cd ~/lib/BearSSL && make CONF=../../stellaris/bearssl/stellaris clean && make CONF=../../stellaris/bearssl/stellaris`

structure: total size, metadata, ctextsize, aessize, encrypted(aes output[actualFirmware], hash), tag, hash, message, 0

# bl_build.py:
bl_build.py is a python script thats main function is to build the bootloader. Additionally, it generates the AES symmetric key as well as the ChaCha20 key. This IV and nonce used for AES and ChaCha are also generated here, all of which are then sent to the secrets.h file. 

We then created associated data that will be used to ensure the authenticitry of the message. This data will be encypted along with the firmware, since, in theory, if the firmware is decoded and the message is not the same since encryption, the message has been tampered with.

The header file is written in C, as to better integrate it with the bootloader.c that will use the keys. This file inlucdes code that isolates the keys into digestable lines for the bootloader to read. 

Lastly, before the bootloader is built, the pathway to the firmware binary is checked and then ran if there are no issues. 

# fw_protect.py
- AES (Advanced Encryption Standard)
The firmware file is encrypted using Advanced Encryption Standard - Galois/Counter Mode. The key and IV are read from the secret_build_output.txt. Using the Pycryptodome library, the firmware is encrypted. AES is a symmetric block cipher that encrypts and decrypts data in blocks of 128 bits. AES-256 is being used which means that it's key size is 256 bits long and that it consists of 14 rounds. 

- SHA-256 
The firmware_blob consists of the metadata and the AES encrypted firmware.  Using the Pycryptodome library, the firmware_blob is hashed. SHA is used to verify the authenticity of the message to make sure that the message was not tampered with. 

- ChaCha20-Poly1305
The second encryption algorithm used is ChaCha20-Poly1305. This encrypts the firmware_blob which consists of the metadata, ciphertext, tag, and hash. Although this algorithm wasn't taught in class, if implemented correctedly, it will make the firmware harder to crack into. 

The firmware_blob is then written to outfile.

## fw_update.py
This firmware updater tool is a Python script designed to update the software on a target device using a UART interface. It sends firmware data to the bootloader in the form of frames and waits for an acknowledgment from the bootloader before proceeding to the next frame.

The script extracts the metadata from the provided firmware file, containing version and size. These are displayed to the user before the update begins. If the version is unsupported (less than the previous one), an error will be raised. The metadata is sent to the bootloader.

The code initiates a handshake with the bootloader by sending "U" to it, indicating that the update process will begin. Once it has responded, the bootloader acknowledged entering update mode.

Before starting the process, the script performs a static size check on the firmware file by comparing its size with a pre-defined static size to ensure that the file is correctly formatted.

During the update, the script prints the progress, indicating the number of frames written and their respective sizes (256 bytes). It verifies that the bootloader responds with an OK message after receiving each frame. The code confirms that the firmware update is done and closes the UART connection.
