mod specification;
use rand::Rng;
use specification::{encrypt_block, mix_subkey, permute, substitute, substitute_inverse};

const ITERATIONS: usize = 0x1000; // 1 out of 10 times i run it with 0x1000 failed...

struct Characteristic {
    /// Delta p
    dp: u16,
    /// Delta u
    du: u16,
    /// Probability
    probability: f64,
}

impl Characteristic {
    /// We can ignore the mix subkeys step as per the paper
    fn simplified_enc_first_3_rounds(input: u16) -> u16 {
        (0..3).fold(input, |data, _| permute(substitute(data)))
    }

    /// Reference: `4.3 Constructing Differential Characteristics`
    fn probability(dp: u16, du: u16) -> Self {
        let mut rng = rand::thread_rng();
        let (mut right, mut wrong) = (0, 0);

        for _ in 0..ITERATIONS {
            let p1: u16 = rng.gen();
            let p2 = p1 ^ dp;

            let u1 = Self::simplified_enc_first_3_rounds(p1);
            let u2 = Self::simplified_enc_first_3_rounds(p2);

            let delta_u = u1 ^ u2;
            if du == delta_u {
                right += 1;
            } else {
                wrong += 1;
            }
        }
        Characteristic {
            dp,
            du,
            probability: right as f64 / (right + wrong) as f64,
        }
    }
}

/// Reference: `4.3 Constructing Differential Characteristics`
fn find_characteristic(offset: usize) -> Characteristic {
    let mut c = Characteristic {
        dp: 0,
        du: 0,
        probability: 0.0,
    };

    for delta_p in 1..0xF {
        let delta_p: u16 = delta_p << 8;

        for delta_u in 0..0xFF {
            let delta_u: u16 = ((delta_u & 0xF0) << (4 + offset)) | ((delta_u & 0xF) << offset);

            let new_c = Characteristic::probability(delta_p, delta_u);
            if new_c.probability > c.probability {
                c = new_c
            }
        }
    }
    c
}

/// 4.4 Extracting Key Bits
mod cipher {
    use super::*;

    pub struct Cipher {
        /// 5 round keys, randomly generated. To simulate an attack,
        /// this is a private data member, only exists in this
        /// `cipher` module.
        ///
        /// The impl function `is_last_round_key` is the only way to
        /// verify if the round key is correctly extracted.
        round_keys: [u16; 5],
    }

    impl Cipher {
        /// randomly generating 5 round keys
        pub fn new() -> Self {
            let mut round_keys: [u16; 5] = [0; 5];
            let mut rng = rand::thread_rng();
            for el in round_keys.iter_mut() {
                *el = rng.gen();
            }
            return Cipher { round_keys };
        }

        pub fn encrypt(&self, plaintext: u16) -> u16 {
            return encrypt_block(plaintext, &self.round_keys);
        }

        pub fn partial_decrypt(&self, block: u16, subkey: u16) -> u16 {
            return substitute_inverse(mix_subkey(block, subkey));
        }

        pub fn is_last_round_key(&self, subkey: u16) -> bool {
            return self.round_keys[4] == subkey;
        }
    }
}

mod attack {
    use super::*;

    /// generating all the sub keys of `bitoffset` dependent masking
    /// 0b1111_0000_1111_0000 or 0b0000_1111_0000_1111
    pub fn subkeys_generator(bitoffset: u16) -> Box<[u16; 256]> {
        assert!(bitoffset == 4 || bitoffset == 0);
        let mut keys = Box::new([0 as u16; 256]);

        // NOTE: no need to mask `i` and `j`, since values in
        // range [0,15) stays within 4 bits
        for i in 0..16 {
            let ki: u16 = i << (8 + bitoffset);
            for j in 0..16 {
                let kj: u16 = j << bitoffset;
                keys[((i * 16) + j) as usize] = ki | kj;
            }
        }

        return keys;
    }

    pub fn extract_partial_subkey(
        cipher: &cipher::Cipher,
        subkeys: &[u16; 256],
        c: &Characteristic,
    ) -> u16 {
        let mut tracker = [0 as u16; 256];
        let mut rng = rand::thread_rng();

        for key_idx in 0..256 {
            let subkey = subkeys[key_idx];

            for _ in 0..ITERATIONS {
                let p1: u16 = rng.gen();
                let p2 = p1 ^ c.dp;

                let c1 = cipher.encrypt(p1);
                let c2 = cipher.encrypt(p2);

                let u1 = cipher.partial_decrypt(c1, subkey);
                let u2 = cipher.partial_decrypt(c2, subkey);

                let _delta_c = c1 ^ c2;
                let delta_u = u1 ^ u2;

                if delta_u == c.du {
                    tracker[key_idx] += 1;
                }
            }
        }

        // find the sub key with max counter.
        let mut max_counter: u16 = 0;
        let mut max_idx: usize = 0;
        for (idx, &el) in tracker.iter().enumerate() {
            if el > max_counter {
                max_counter = el;
                max_idx = idx;
            }
        }

        return subkeys[max_idx];
    }
}

fn main() {
    let cipher = cipher::Cipher::new();

    // finding characteristics
    let ca = find_characteristic(0);
    let cb = find_characteristic(4);

    // extracting subkeys
    let subkey1 = attack::subkeys_generator(0);
    let subkey1 = attack::extract_partial_subkey(&cipher, &subkey1, &ca);

    let subkey2 = attack::subkeys_generator(4);
    let subkey2 = attack::extract_partial_subkey(&cipher, &subkey2, &cb);

    // concat and compare
    let subkey = subkey1 | subkey2;

    if cipher.is_last_round_key(subkey) {
        println!("sub key found!\n{:#018b}", subkey);
    } else {
        println!("failed to find sub key");
    }
}
