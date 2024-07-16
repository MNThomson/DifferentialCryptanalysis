mod specification;

fn main() {
    let enc = specification::encrypt_block(1, &[1, 2, 3, 4, 5]);
    println!("Enc: {}", enc);
}
