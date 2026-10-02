// This software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Benchmarks for PQC memory pool

#![allow(clippy::unwrap_used, clippy::expect_used)]

use saorsa_transport::crypto::pqc::memory_pool::{PoolConfig, PqcMemoryPool};

use saorsa_transport::crypto::pqc::types::*;

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use std::time::Duration;

fn bench_pool_allocation(c: &mut Criterion) {
    let pool = PqcMemoryPool::new(PoolConfig {
        initial_size: 10,
        max_size: 100,
        growth_increment: 5,
        acquire_timeout: Duration::from_secs(1),
    });

    c.bench_function("pool_ml_kem_public_key", |b| {
        b.iter(|| {
            let guard = pool.acquire_ml_kem_public_key().unwrap();
            black_box(&guard);
            // Guard automatically returned on drop
        });
    });
}

fn bench_direct_allocation(c: &mut Criterion) {
    c.bench_function("direct_ml_kem_public_key", |b| {
        b.iter(|| {
            let buffer = Box::new([0u8; ML_KEM_768_PUBLIC_KEY_SIZE]);
            black_box(&buffer);
        });
    });
}

fn bench_pool_secret_key(c: &mut Criterion) {
    let pool = PqcMemoryPool::new(PoolConfig::default());

    c.bench_function("pool_ml_kem_secret_key", |b| {
        b.iter(|| {
            let mut guard = pool.acquire_ml_kem_secret_key().unwrap();
            // Simulate some work
            guard.as_mut().0[0] = 42;
            black_box(&guard);
            // Guard automatically zeros and returns on drop
        });
    });
}

fn bench_concurrent_pool_access(c: &mut Criterion) {
    use std::sync::Arc;
    use std::thread;

    let pool = Arc::new(PqcMemoryPool::new(PoolConfig {
        initial_size: 20,
        max_size: 100,
        growth_increment: 10,
        acquire_timeout: Duration::from_secs(1),
    }));

    c.bench_function("concurrent_pool_access", |b| {
        b.iter(|| {
            let mut handles = vec![];

            for _ in 0..4 {
                let pool_clone = pool.clone();
                let handle = thread::spawn(move || {
                    for _ in 0..5 {
                        let _guard = pool_clone.acquire_ml_kem_ciphertext().unwrap();
                        // Simulate some work
                        std::thread::yield_now();
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }
        });
    });
}

criterion_group!(
    benches,
    bench_pool_allocation,
    bench_direct_allocation,
    bench_pool_secret_key,
    bench_concurrent_pool_access
);

criterion_main!(benches);
