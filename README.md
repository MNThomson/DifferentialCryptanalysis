# Differential Cryptanalysis

Final project for **ECE 406: Applied Cryptography**.

An implementation of differential cryptanalysis outlined in Section 4 of this paper on
[Linear Differential Cryptanalysis](https://www.engr.mun.ca/~howard/PAPERS/ldc_tutorial.pdf).

Contributors:

- Max Thomson - V00969053
- Hal Nguyen - V00972322

## Cipher overview

The program will generate 5 secret round keys randomly before performing the differential
cryptanalysis attack. These 5 keys are private, and cannot be accessed in other parts of the
program, the implementation of `cipher::Cipher` exposes a function `is_last_round_key` to verified
for the correctness of the extracted (last) round key.

## Usage:

```sh
cargo run --release
```

The flag `--release` builds the binary in release mode, which will apply the optimizations it needs
for a faster run-time.
