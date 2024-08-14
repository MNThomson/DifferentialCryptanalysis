mod specification;
use chrono::Utc;
use rand::Rng;
use specification::{encrypt_block, mix_subkey, permute, substitute, substitute_inverse};
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

/// arbitrary large number
const ITERATIONS: usize = 0xffff;

#[derive(Debug, Clone)]
struct Characteristic {
    /// Delta p
    dp: u16,
    /// Delta u
    du: u16,
    /// Probability
    probability: f64,
}

fn to_bin_string(n: u16) -> String {
    format!("{:#05}\t{:#06x}\t{:#018b}", n, n, n)
}

impl std::fmt::Display for Characteristic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "\tdelta_p:\t{}\n\tdelta_u:\t{}",
            to_bin_string(self.dp),
            to_bin_string(self.du)
        )
    }
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
fn find_characteristic(offset: u8) -> Characteristic {
    let c = Arc::new(Mutex::new(Characteristic {
        dp: 0,
        du: 0,
        probability: 0.0,
    }));

    let pool = threadpool::ThreadPool::new(16);

    for delta_p in 1..0xF {
        let c = Arc::clone(&c);
        pool.execute(move || {
            let delta_p: u16 = delta_p << 8;

            for delta_u in 0..0xFF {
                let delta_u: u16 = ((delta_u & 0xF0) << (4 + offset)) | ((delta_u & 0xF) << offset);

                let new_c = Characteristic::probability(delta_p, delta_u);
                let mut c = c.lock().unwrap();
                if new_c.probability > c.probability {
                    *c = new_c
                }
            }
        });
    }

    pool.join();

    let c = c.lock().unwrap().to_owned();
    println!("\nCharacteristic found:\n{}", c);
    c
}

/// Reference: 4.4 Extracting Key Bits
mod cipher {
    use std::fmt::Display;

    use super::*;

    #[derive(Debug)]
    pub struct Cipher {
        /// 5 round keys, randomly generated.
        pub round_keys: [u16; 5],
    }

    impl Display for Cipher {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let round_keys = self.round_keys.map(|k| to_bin_string(k)).join("\n\t");
            write!(f, "{}", round_keys)
        }
    }

    impl Cipher {
        /// randomly generating 5 round keys
        pub fn new() -> Self {
            let mut round_keys: [u16; 5] = [0; 5];
            let mut rng = rand::thread_rng();
            for el in round_keys.iter_mut() {
                *el = rng.gen();
            }
            Cipher { round_keys }
        }

        pub fn encrypt(&self, plaintext: u16) -> u16 {
            encrypt_block(plaintext, &self.round_keys)
        }

        pub fn partial_decrypt(&self, block: u16, subkey: u16) -> u16 {
            substitute_inverse(mix_subkey(block, subkey))
        }
    }
}

mod attack {
    use super::*;

    /// Generating all subkeys with bit masking of
    /// 0b1111_0000_1111_0000 or 0b0000_1111_0000_1111.
    /// The bitoffset value can only be 0 or 4.
    pub fn subkey_generator(bitoffset: u8) -> [u16; 256] {
        assert!(bitoffset == 4 || bitoffset == 0);

        let mut keys = [0_u16; 256];
        let mut index = 0_usize;

        // NOTE: no need to mask `i` and `j`, values in
        // range [0,16) stay within 4 bits
        for i in 0..16 {
            let ki: u16 = i << (8 + bitoffset);
            for j in 0..16 {
                let kj: u16 = j << bitoffset;
                keys[index] = ki | kj;
                index += 1;
            }
        }

        keys
    }

    pub fn extract_partial_subkey(
        cipher: Arc<cipher::Cipher>,
        subkeys: &[u16; 256],
        c: Characteristic,
    ) -> u16 {
        let c = Arc::new(c);
        let tracker = Arc::new(Mutex::new([0_u16; 256]));

        let pool = threadpool::ThreadPool::new(10);

        subkeys.iter().enumerate().for_each(|(key_idx, &subkey)| {
            for _ in 0..10 {
                let tracker = Arc::clone(&tracker);
                let c = Arc::clone(&c);
                let cipher = Arc::clone(&cipher);

                pool.execute(move || {
                    let mut rng = rand::thread_rng();
                    for _ in 0..ITERATIONS / 10 {
                        let p1: u16 = rng.gen();

                        let p2 = p1 ^ c.dp;

                        let c1 = cipher.encrypt(p1);
                        let c2 = cipher.encrypt(p2);

                        let u1 = cipher.partial_decrypt(c1, subkey);
                        let u2 = cipher.partial_decrypt(c2, subkey);

                        let delta_u = u1 ^ u2;

                        if delta_u == c.du {
                            tracker.lock().unwrap()[key_idx] += 1;
                        }
                    }
                });
            }
        });

        pool.join();

        // subkeys with max counter.
        let tracker = tracker.lock().unwrap();

        let mut max_ctr: u16 = 0;
        let mut max_idx: usize = 0;
        tracker.iter().enumerate().for_each(|(idx, &ctr)| {
            if ctr > max_ctr {
                max_ctr = ctr;
                max_idx = idx;
            }
        });

        subkeys[max_idx]
    }
}

enum BitOffset {
    /// offset for 0x0f0f
    Zero,
    /// offset for 0xf0f0
    One,
}

impl BitOffset {
    fn val(&self) -> u8 {
        match self {
            Self::Zero => 0,
            Self::One => 4,
        }
    }
}

fn main() {
    let cipher = Arc::new(cipher::Cipher::new());
    println!("Cipher's round keys:\n\t{}", cipher);

    let start_time = Utc::now().time();

    let c = Arc::clone(&cipher);
    let t1 = thread::spawn(move || crack(BitOffset::Zero, c));

    let c = Arc::clone(&cipher);
    let t2 = thread::spawn(move || crack(BitOffset::One, c));

    let keypart_1 = t1.join().unwrap();
    let keypart_2 = t2.join().unwrap();

    let end_time = Utc::now().time();

    let final_round_key = keypart_1 | keypart_2;

    print!("\n");
    if final_round_key == cipher.round_keys[4] {
        println!("Correct round key extracted: ");
    } else {
        println!("Incorrect round key extracted: ");
    }

    println!("\t{}\n", to_bin_string(final_round_key));
    let diff = end_time - start_time;
    println!("Done in {}ms", diff.num_milliseconds());
}

fn crack(bitoffset: BitOffset, cipher: Arc<cipher::Cipher>) -> u16 {
    let ca = find_characteristic(bitoffset.val());
    let subkeys1 = attack::subkey_generator(bitoffset.val());
    attack::extract_partial_subkey(cipher, &subkeys1, ca)
}
