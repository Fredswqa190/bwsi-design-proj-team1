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

# fw_protect.py
- AES (Advanced Encryption Standard)
The firmware file is encrypted using Advanced Encryption Standard - Galois/Counter Mode. The key and IV are read from the secret_build_output.txt. Using the Pycryptodome library, the firmware is encrypted. AES is a symmetric block cipher that encrypts and decrypts data in blocks of 128 bits. AES-256 is being used which means that it's key size is 256 bits long and that it consists of 14 rounds. 

- SHA-256 
The firmware_blob consists of the metadata and the AES encrypted firmware.  Using the Pycryptodome library, the firmware_blob is hashed. SHA is used to verify the authenticity of the message to make sure that the message was not tampered with. 

- ChaCha20-Poly1305
The second encryption algorithm used is ChaCha20-Poly1305. This encrypts the firmware_blob which consists of the metadata, ciphertext, tag, and hash. Although this algorithm wasn't taught in class, if implemented correctedly, it will make the firmware harder to crack into. 

The firmware_blob is then written to outfile.