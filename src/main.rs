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
    fn simplified_enc_first_3_rounds(plaintext: u16) -> u16 {
        //
        let mut text = plaintext;
        for _ in 0..3 {
            text = substitute(text);
            text = permute(text);
        }
        text
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

/// Reference: `4.3 Constructing Differential Characteristics`
fn find_characteristic() -> Characteristic {
    let mut c = Characteristic {
        dp: 0,
        du: 0,
        probability: 0.0,
    };

    for delta_p in 1..0xF {
        let delta_p = (delta_p << 8) as u16;

        for delta_u in 0..0xFF {
            let delta_u = (((delta_u & 0xF0) << 4) | (delta_u & 0xF)) as u16;

            let new_c = Characteristic::probability(delta_p, delta_u);
            if new_c.probability > c.probability {
                c = new_c
            }
        }
    }
    c
}

fn main() {
    let ca = find_characteristic();
    println!("Differential Characteristic A: {:?}", ca);
}
