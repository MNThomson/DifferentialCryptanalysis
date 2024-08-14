# Differential Cryptanalysis

Final project for **ECE 406: Applied Cryptography**.

This project implements differential cryptanalysis to attack a simple cipher,
as outlined in
[Linear Differential Cryptanalysis](https://www.engr.mun.ca/~howard/PAPERS/ldc_tutorial.pdf).
The program utilizes multithreading to enhance performance, making the analysis faster and more efficient.


## Usage

To run the project, use the following command:

```sh
cargo r
```

This will output

```txt
Cipher's round keys:
        40618   0x9eaa  0b1001111010101010
        48064   0xbbc0  0b1011101111000000
        09059   0x2363  0b0010001101100011
        58711   0xe557  0b1110010101010111
        07904   0x1ee0  0b0001111011100000

Characteristic found:
        delta_p:        01280   0x0500  0b0000010100000000
        delta_u:        24672   0x6060  0b0110000001100000

Characteristic found:
        delta_p:        02816   0x0b00  0b0000101100000000
        delta_u:        01542   0x0606  0b0000011000000110

Correct round key extracted:
        07904   0x1ee0  0b0001111011100000

Done in 1857ms
```

## Contributors

- [Max Thomson](https://github.com/MNThomson/)
- [Hal Nguyen](https://github.com/hn275/)
