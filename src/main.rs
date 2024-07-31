mod specification;
use rand::Rng;
use specification::{permute, substitute};

#[derive(Debug)]
#[allow(dead_code)]
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

        for _ in 0..0x1000 {
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

impl std::fmt::Display for Characteristic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "\tdelta_P: {:#018b}\n\tdelta_U: {:#018b}\n\tprobability: {}\n",
            self.dp, self.du, self.probability
        )
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

fn subkeys_generator(bitoffset: u16) -> Box<[u16; 256]> {
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

fn extract_subkey(subkeys: &[u16; 256]){}

fn main() {
    let ca = find_characteristic(0);
    let _subkey1 = subkeys_generator(0);
    for key in _subkey1.iter() {
        println!("{:016b}", key);
    }

    let cb = find_characteristic(4);
    let _subkey2 = subkeys_generator(4);
    for key in _subkey2.iter() {
        println!("{:016b}", key);
    }

    println!("Differential Characteristics:\nA:\n{}\nB:\n{}", ca, cb);
}
