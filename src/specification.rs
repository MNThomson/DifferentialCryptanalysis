pub const KEY_SIZE: usize = 16;
pub const SBOX: [u16; KEY_SIZE] = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7];
pub const SBOX_INV: [u16; KEY_SIZE] = create_sbox_inv(SBOX);
pub const PERMUTATION: [u16; KEY_SIZE] = [1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16];

pub fn substitute(val: u16) -> u16 {
    let mut result = 0;
    for i in 0..4 {
        result |= SBOX[((val >> (i * 4)) & 0xF) as usize] << (i * 4);
    }
    result
}

pub fn substitute_inverse(val: u16) -> u16 {
    let mut result = 0;
    for i in 0..4 {
        result |= SBOX_INV[((val >> (i * 4)) & 0xF) as usize] << (i * 4);
    }
    result
}

pub fn permute(val: u16) -> u16 {
    let mut result = 0;
    (0..KEY_SIZE).for_each(|i| {
        result |= ((val >> (KEY_SIZE - i - 1)) & 1) << (KEY_SIZE - PERMUTATION[i] as usize);
    });
    result
}

pub fn mix_subkey(val: u16, subkey: u16) -> u16 {
    val ^ subkey
}

pub fn encrypt_block(block: u16, keys: &[u16]) -> u16 {
    let mut block = block;
    (0..3).for_each(|i| {
        block = mix_subkey(block, keys[i]);
        block = substitute(block);
        block = permute(block);
    });
    block = mix_subkey(block, keys[3]);
    block = substitute(block);
    block = mix_subkey(block, keys[4]);
    block
}

/// for testing
#[allow(dead_code)]
pub fn decrypt_block(block: u16, keys: &[u16]) -> u16 {
    let mut block = block;
    block = mix_subkey(block, keys[4]);
    block = substitute_inverse(block);
    block = mix_subkey(block, keys[3]);

    (0..3).rev().for_each(|i| {
        block = permute(block);
        block = substitute_inverse(block);
        block = mix_subkey(block, keys[i]);
    });
    block
}

const fn create_sbox_inv(sbox: [u16; KEY_SIZE]) -> [u16; KEY_SIZE] {
    let mut inv = [0u16; KEY_SIZE];
    let mut i = 0;
    while i < KEY_SIZE {
        inv[sbox[i] as usize] = i as u16;
        i += 1;
    }
    inv
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_mix_subkey() {
        assert_eq!(mix_subkey(0x1, 0x5), 0x4);
        assert_eq!(mix_subkey(0xF, 0x0), 0xF);
        assert_eq!(mix_subkey(0x0, 0xF), 0xF);
    }

    #[test]
    fn test_substitute() {
        assert_eq!(substitute(0x1234), 0x4D12);
        assert_eq!(substitute(0xFFFF), 0x7777);
        assert_eq!(substitute(0x0000), 0xEEEE);
    }

    #[test]
    fn test_substitute_inverse() {
        assert_eq!(substitute_inverse(0x4D12), 0x1234);
        assert_eq!(substitute_inverse(0x7777), 0xFFFF);
        assert_eq!(substitute_inverse(0xEEEE), 0x0000);
    }

    #[test]
    fn test_substitute_symmetry() {
        assert_eq!(substitute_inverse(substitute(0x1234)), 0x1234);
        assert_eq!(substitute_inverse(substitute(0xFFFF)), 0xFFFF);
        assert_eq!(substitute_inverse(substitute(0x0000)), 0x0000);
    }

    #[test]
    fn test_permute() {
        assert_eq!(permute(0x1234), 0x016A);
        assert_eq!(permute(0xFFFF), 0xFFFF);
        assert_eq!(permute(0x0000), 0x0000);
    }

    #[test]
    fn test_encrypt_block() {
        let keys = [0x1111, 0x2222, 0x3333, 0x4444, 0x5555];
        assert_eq!(encrypt_block(0x1234, &keys), 0x1FBC);
        assert_eq!(encrypt_block(0xFFFF, &keys), 0x7F79);
        assert_eq!(encrypt_block(0x0000, &keys), 0x7CB9);
    }

    #[test]
    fn test_encrypt_decrypt_symmetry() {
        let keys = [0x1111, 0x2222, 0x3333, 0x4444, 0x5555];
        assert_eq!(decrypt_block(encrypt_block(0x1234, &keys), &keys), 0x1234);
    }
}
