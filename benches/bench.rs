use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cryptanalysis::specification::*;

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("substitute", |b| {
        b.iter(|| substitute(black_box(0x1234), black_box(SBOX)))
    });

    c.bench_function("mix_subkey", |b| {
        b.iter(|| mix_subkey(black_box(0x1234), black_box(0x5678)))
    });

    c.bench_function("permute", |b| b.iter(|| permute(black_box(0x1234))));

    let keys = [0x1111, 0x2222, 0x3333, 0x4444, 0x5555];

    c.bench_function("encrypt_block", |b| {
        b.iter(|| encrypt_block(black_box(0x1234), black_box(&keys)))
    });

    c.bench_function("decrypt_block", |b| {
        b.iter(|| decrypt_block(black_box(0x1234), black_box(&keys)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
