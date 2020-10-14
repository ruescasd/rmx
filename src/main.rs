#![allow(warnings)]

extern crate rand_core;
extern crate curve25519_dalek;
extern crate rand;
extern crate sha2;

use curve25519_dalek::ristretto::{RistrettoPoint};
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::scalar::{Scalar};
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT, BASEPOINT_ORDER};

use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::U32;
use rand_core::OsRng;
use rand::Rng;

mod hashing;
mod elgamal;
mod element;

use elgamal::*;

//
// based on
// https://fc17.ifca.ai/voting/papers/voting17_HLKD17.pdf
// 

pub struct yChallengeInput<'a> {
    pub es: &'a Vec<Ciphertext>,
    pub e_primes: &'a Vec<Ciphertext>,
    pub cs: &'a Vec<RistrettoPoint>,
    pub c_hats: &'a Vec<RistrettoPoint>,
    pub pk: &'a PublicKey
}

pub struct tChallengeInput {
    pub t1: RistrettoPoint,
    pub t2: RistrettoPoint,
    pub t3: RistrettoPoint,
    pub t4_1: RistrettoPoint,
    pub t4_2: RistrettoPoint,
    pub t_hats: Vec<RistrettoPoint>
}

pub struct Responses {
    s1: Scalar,
    s2: Scalar,
    s3: Scalar,
    s4: Scalar,
    s_hats: Vec<Scalar>,
    s_primes: Vec<Scalar>
}

pub struct Proof {
    t: tChallengeInput,
    s: Responses,
    cs: Vec<RistrettoPoint>,
    c_hats: Vec<RistrettoPoint>
}

fn main() {
    let mut csprng = OsRng;
    let sk = PrivateKey::random(&mut csprng);
    let pk = sk.public_key();

    let mut es: Vec<Ciphertext> = Vec::with_capacity(10);

    for _ in 0..10 {
        let plaintext: RistrettoPoint = RistrettoPoint::random(&mut csprng);
        let h = hashing::hash_bytes(plaintext.compress().as_bytes().to_vec());
        let s = hashing::hex(h.as_slice());
        println!("{:?}", s);
        let c = pk.encrypt(plaintext, &mut csprng);
        es.push(c);
    }
    
    let generators = generators(es.len() + 1);
    let (e_primes, rs, perm) = gen_shuffle(&es, &pk);
    
    println!("{:?}", perm);

    for &c in e_primes.iter() {
        let h = hashing::hash_bytes(sk.decrypt(c).compress().as_bytes().to_vec());
        let s = hashing::hex(h.as_slice());
        println!("{:?}", s);
    }
    
    let proof = gen_proof(&es, &e_primes, &rs, &perm, &pk, &generators);
    let ok = check_proof(&proof, &es, &e_primes, &pk, &generators);
    println!("ok is {}", ok); 
}

use std::mem::{self, MaybeUninit};

fn gen_shuffle(ciphertexts: &Vec<Ciphertext>, pk: &PublicKey) -> (Vec<Ciphertext>, Vec<Scalar>, Vec<usize>) {
    let mut csprng = OsRng;
    let perm: Vec<usize> = gen_permutation(ciphertexts.len());
    
    let mut e_primes = Vec::with_capacity(ciphertexts.len());
    let mut rs = Vec::with_capacity(ciphertexts.len());

    unsafe { 
        rs.set_len(ciphertexts.len());
        for i in 0..perm.len() {
            let c = ciphertexts[perm[i]];
    
            let r = Scalar::random(&mut csprng);
            let a = c.a + (r * pk.0);
            let b = c.b + (r * RISTRETTO_BASEPOINT_POINT);
            let c_ = Ciphertext {
                a: a, 
                b: b
            };
            e_primes.push(c_);
            rs[perm[i]] = r;
        }
    }
     
    (e_primes, rs, perm)
}

fn gen_proof(es: &Vec<Ciphertext>, e_primes: &Vec<Ciphertext>, r_primes: &Vec<Scalar>, 
    perm: &Vec<usize>, pk: &PublicKey, generators: &Vec<RistrettoPoint>) -> Proof {

    let mut csprng = OsRng;
    
    let N = es.len();
    let h_generators = &generators[1..].to_vec();
    let h_initial = generators[0];
    
    assert!(N == e_primes.len());
    assert!(N == r_primes.len());
    assert!(N == perm.len());
    assert!(N == h_generators.len());

    let (cs, rs) = gen_commitments(&perm, h_generators);
    let us = hashing::shuffle_proof_us(&es, &e_primes, &cs, N);
    
    let mut u_primes: Vec<Scalar> = Vec::with_capacity(N);
    for &i in perm.iter() {
        u_primes.push(us[i]);
    }
    
    let (c_hats, r_hats) = gen_commitment_chain(h_initial, &u_primes);
    
    let r_bar: Scalar = rs.iter().sum();
    
    let mut vs = vec![Scalar::one();perm.len()];
    for i in (0..(perm.len() - 1)).rev() {
        vs[i] = u_primes[i+1] * vs[i+1];
    }
    
    let mut r_hat: Scalar = (r_hats[0] * vs[0]);
    for i in 1..r_hats.len() {
        r_hat = r_hat + (r_hats[i] * vs[i]);
    }
    
    let mut r_tilde: Scalar = (rs[0] * us[0]);
    for i in 1..rs.len() {
        r_tilde = r_tilde + (rs[i] * us[i]);
    }
    
    let mut r_prime: Scalar = (r_primes[0] * us[0]);
    for i in 1..r_primes.len() {
        r_prime = r_prime + (r_primes[i] * us[i])
    }
    
    let omegas = vec![Scalar::random(&mut csprng);4];
    let omega_hats = vec![Scalar::random(&mut csprng);N];
    let omega_primes = vec![Scalar::random(&mut csprng);N];
    
    let t1 = RISTRETTO_BASEPOINT_POINT * omegas[0];
    let t2 = RISTRETTO_BASEPOINT_POINT * omegas[1];

    let mut t3_temp = (h_generators[0] * omega_primes[0]);
    let mut t4_1_temp = (e_primes[0].a * omega_primes[0]);
    let mut t4_2_temp = (e_primes[0].b * omega_primes[0]);
    for i in 1..N {
        t3_temp = t3_temp + (h_generators[i] * omega_primes[i]);
        t4_1_temp = t4_1_temp + (e_primes[i].a * omega_primes[i]);
        t4_2_temp = t4_2_temp + (e_primes[i].b * omega_primes[i]);
    }
    
    let t3 = (RISTRETTO_BASEPOINT_POINT * omegas[2]) + t3_temp;
    let t4_1 = (pk.0 * (-omegas[3])) + t4_1_temp;
    let t4_2 = (RISTRETTO_BASEPOINT_POINT * (-omegas[3])) + t4_2_temp;

    let mut t_hats: Vec<RistrettoPoint> = Vec::with_capacity(N);
    for i in 0..c_hats.len() {
        let previous_c = if i == 0 {
            h_initial 
        } else {
            c_hats[i-1]
        };
        
        let next = (RISTRETTO_BASEPOINT_POINT * omega_hats[i]) + (previous_c * omega_primes[i]);
        t_hats.push(next);
    }
 
    let y = yChallengeInput {
        es: es,
        e_primes: e_primes,
        cs: &cs,
        c_hats: &c_hats,
        pk: pk
    };

    let t = tChallengeInput {
        t1,
        t2,
        t3,
        t4_1,
        t4_2,
        t_hats
    };

    let c: Scalar = hashing::shuffle_proof_challenge(&y, &t);
    
    let s1 = omegas[0] + (c * r_bar);
    let s2 = omegas[1] + (c * r_hat);
    let s3 = omegas[2] + (c * r_tilde);
    let s4 = omegas[3] + (c * r_prime);

    let mut s_hats: Vec<Scalar> = Vec::with_capacity(N);
    let mut s_primes: Vec<Scalar> = Vec::with_capacity(N);
    for i in 0..N {
        s_hats.push(omega_hats[i] 
            + (c * r_hats[i]));
        s_primes.push(omega_primes[i] 
            + (c * u_primes[i]))
    }

    let s = Responses {
        s1,
        s2,
        s3,
        s4,
        s_hats,
        s_primes
    };

    Proof {
        t,
        s,
        cs,
        c_hats
    }
}

fn check_proof(proof: &Proof, es: &Vec<Ciphertext>, e_primes: &Vec<Ciphertext>, 
    pk: &PublicKey, generators: &Vec<RistrettoPoint>) -> bool {
    
    let N = es.len();
    let h_generators = &generators[1..].to_vec();
    let h_initial = generators[0];
    
    assert!(N == e_primes.len());
    assert!(N == h_generators.len());

    let us = hashing::shuffle_proof_us(es, e_primes, &proof.cs, N);

    let mut c_bar_num: RistrettoPoint = proof.cs[0];
    let mut c_bar_den: RistrettoPoint = h_generators[0];
    let mut u: Scalar = us[0];
    let mut c_tilde: RistrettoPoint = proof.cs[0] * us[0];
    let mut a_prime: RistrettoPoint = es[0].a * us[0];
    let mut b_prime: RistrettoPoint = es[0].b * us[0];
    let mut t_tilde3_temp: RistrettoPoint = h_generators[0] * proof.s.s_primes[0];
    let mut t_tilde41_temp: RistrettoPoint = e_primes[0].a * proof.s.s_primes[0];
    let mut t_tilde42_temp: RistrettoPoint = e_primes[0].b * proof.s.s_primes[0];

    for i in 1..N {
        c_bar_num = c_bar_num + proof.cs[i];
        c_bar_den = c_bar_den + h_generators[i];
        u = u * us[i];
        c_tilde = c_tilde + (proof.cs[i] * us[i]);
        a_prime = a_prime + (es[i].a * us[i]);
        b_prime = b_prime + (es[i].b * us[i]);
        t_tilde3_temp = t_tilde3_temp + (h_generators[i] * proof.s.s_primes[i]);
        t_tilde41_temp = t_tilde41_temp + (e_primes[i].a * proof.s.s_primes[i]);
        t_tilde42_temp = t_tilde42_temp + (e_primes[i].b * proof.s.s_primes[i]);
    }
    let c_bar = c_bar_num - c_bar_den;
    let c_hat = proof.c_hats[N - 1] - (h_initial * u);

    let y = yChallengeInput {
        es: es,
        e_primes: e_primes,
        cs: &proof.cs,
        c_hats: &proof.c_hats,
        pk: pk
    };

    let c = hashing::shuffle_proof_challenge(&y, &proof.t);
    let t_prime1 = (c_bar * (-c)) + (RISTRETTO_BASEPOINT_POINT * proof.s.s1);
    let t_prime2 = (c_hat * (-c)) + (RISTRETTO_BASEPOINT_POINT * proof.s.s2);
    let t_prime3 = (c_tilde * (-c)) + (RISTRETTO_BASEPOINT_POINT * proof.s.s3) + t_tilde3_temp;    
    let t_prime41 = (a_prime * (-c)) + (pk.0 * (-proof.s.s4)) + t_tilde41_temp;
    let t_prime42 = (b_prime * (-c)) + (RISTRETTO_BASEPOINT_POINT * (-proof.s.s4)) + t_tilde42_temp;

    let mut t_hat_primes = Vec::with_capacity(N);
    for i in 0..N {
        let c_term = if i == 0 {
            h_initial
        } else {
            proof.c_hats[i - 1]
        };
        let next = (proof.c_hats[i] * (-c)) + (RISTRETTO_BASEPOINT_POINT * proof.s.s_hats[i]) 
            + (c_term * proof.s.s_primes[i]);
        
        t_hat_primes.push(next);
    }

    let mut checks = Vec::with_capacity(5 + N);
    checks.push(proof.t.t1 == t_prime1);
    checks.push(proof.t.t2 == t_prime2);
    checks.push(proof.t.t3 == t_prime3);
    checks.push(proof.t.t4_1 == t_prime41);
    checks.push(proof.t.t4_2 == t_prime42);
    for i in 0..N {
        checks.push(proof.t.t_hats[i] == t_hat_primes[i]);
    }
    
    return !checks.contains(&false);
}

fn gen_commitments(perm: &Vec<usize>, generators: &Vec<RistrettoPoint>)  -> (Vec<RistrettoPoint>, Vec<Scalar>) {
    let mut csprng = OsRng;

    assert!(generators.len() == perm.len());
    
    let mut rs = vec![Scalar::zero();perm.len()];
    let mut cs = vec![RistrettoPoint::default();perm.len()];
    for i in 0..perm.len() {
        let r = Scalar::random(&mut csprng);
        let c = generators[i] + (RISTRETTO_BASEPOINT_POINT * r);
        rs[perm[i]] = r;
        cs[perm[i]] = c;
    }
    (cs, rs)
}

fn gen_commitment_chain(initial: RistrettoPoint, us: &Vec<Scalar>)  -> (Vec<RistrettoPoint>, Vec<Scalar>) {
    let mut csprng = OsRng;
    let mut cs: Vec<RistrettoPoint> = Vec::with_capacity(us.len());
    let mut rs: Vec<Scalar> = Vec::with_capacity(us.len());
    
    for i in 0..us.len() {
        let r = Scalar::random(&mut csprng);
        let c_temp = if i == 0 {
            initial
        } else {
            cs[i-1]
        };
        let c = (RISTRETTO_BASEPOINT_POINT * r)  + (c_temp * us[i]);

        cs.push(c);
        rs.push(r);
    }

    (cs, rs)
}

// FIXME not kosher
fn generators(size: usize) -> Vec<RistrettoPoint> {
    let mut csprng = OsRng;
    let mut ret: Vec<RistrettoPoint> = Vec::with_capacity(size);
    
    for _ in 0..size {
        let g: RistrettoPoint = RistrettoPoint::random(&mut csprng);
        ret.push(g);
    }

    ret
}

fn gen_permutation(size: usize) -> Vec<usize> {
    let mut ret = Vec::with_capacity(size);
    let mut rng = rand::thread_rng();

    let mut ordered: Vec<usize> = (0..size).collect();

    for i in 0..size {
        let k = rng.gen_range(i, size);
        let j = ordered[k];
        ordered[k] = ordered[i];
        ret.push(j);
    }

    return ret;
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_shuffle() {
        let mut csprng = OsRng;
        let sk = PrivateKey::random(&mut csprng);
        let pk = sk.public_key();
        let mut es: Vec<Ciphertext> = Vec::with_capacity(10);

        let N = 100;

        for _ in 0..N {
            let plaintext: RistrettoPoint = RistrettoPoint::random(&mut csprng);
            let c = pk.encrypt(plaintext, &mut csprng);
            es.push(c);
        }
        
        let mut hs = generators(es.len() + 1);
        let (mut e_primes, mut rs, mut perm) = gen_shuffle(&es, &pk);
        let mut proof = gen_proof(&es, &e_primes, &rs, &perm, &pk, &hs);
        let mut ok = check_proof(&proof, &es, &e_primes, &pk, &hs);
        assert_eq!(ok, true);

        let mut hs = generators(es.len() + 1);
        let (mut e_primes, mut rs, mut perm) = gen_shuffle(&es, &pk);
        
        // inject a fake ciphertext at a random index
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0, N);
        let fake: RistrettoPoint = RistrettoPoint::random(&mut csprng);
        let c_fake = pk.encrypt(fake, &mut csprng);
        e_primes[index] = c_fake;
        
        let mut proof = gen_proof(&es, &e_primes, &rs, &perm, &pk, &hs);
        let mut ok = check_proof(&proof, &es, &e_primes, &pk, &hs);
        assert_eq!(ok, false);
    }

   

    #[test]
    fn test_uninit() {
        let data = {
        
            let mut data: [MaybeUninit<u32>; 10] = unsafe {
                MaybeUninit::uninit().assume_init()
            };

            for i in 0..10 {
                data[i] = MaybeUninit::new(i as u32);
            }

            unsafe { mem::transmute::<_, [u32; 10]>(data) }
        };

        let v: Vec<u32> = (0u32..10u32).collect();
        assert_eq!(data.to_vec(), v);

    }

    #[test]
    fn test_uninit2() {
        
        let mut v: Vec<Ciphertext> = Vec::with_capacity(10);
        unsafe { 
            v.set_len(10);
        }
        v[0] = Ciphertext { 
            a: RistrettoPoint::default(), 
            b: RistrettoPoint::default()
        };
        
        println!("{:?}", v);
    }
}
