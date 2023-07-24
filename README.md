# bwsi-design-proj-team1

# reading is hard so dont make me do this.

# README

## Running the insecure example

1. Build the firmware by navigating to `firmware/firmware`, and running `make`.
2. Build the bootloader by navigating to `tools`, and running `python bl_build.py`
2. Run the bootloader by navigating to `tools`, and running `python bl_emulate.py`

## Troubleshooting

Ensure that BearSSL is compiled for the stellaris: `cd ~/lib/BearSSL && make CONF=../../stellaris/bearssl/stellaris clean && make CONF=../../stellaris/bearssl/stellaris`
