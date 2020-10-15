use curve25519_dalek::ristretto::{RistrettoPoint};
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT, BASEPOINT_ORDER};
use sha2::{Sha256, Sha512, Digest};
use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::U32;
use curve25519_dalek::scalar::Scalar;

use crate::elgamal::Ciphertext;
use crate::{yChallengeInput, tChallengeInput};

pub trait ByteSource {
    fn get_bytes(&self) -> Vec<u8>;
}

impl ByteSource for Ciphertext {
    fn get_bytes(&self) -> Vec<u8> {
        let mut a = self.a.compress().to_bytes().to_vec();
        a.extend_from_slice(&self.b.compress().to_bytes());

        a
    }
}

impl ByteSource for RistrettoPoint {
    fn get_bytes(&self) -> Vec<u8> {
        return self.compress().to_bytes().to_vec();
    }
}

impl ByteSource for Scalar {
    fn get_bytes(&self) -> Vec<u8> {
        return self.as_bytes().to_vec();
    }
}

fn concat_bytes<T: ByteSource>(cs: &Vec<T>) -> Vec<u8> {
    return 
        cs.iter()
        .map(|x| x.get_bytes())
        .fold(vec![], |mut a, b| {
            a.extend(b);
            a
        });
}

pub fn shuffle_proof_us(es: &Vec<Ciphertext>, e_primes: &Vec<Ciphertext>, cs: &Vec<RistrettoPoint>, n: usize) -> Vec<Scalar> {
    let mut prefix_vector = concat_bytes(es);
    prefix_vector.extend(concat_bytes(e_primes));
    prefix_vector.extend(concat_bytes(cs));
    let prefix = prefix_vector.as_slice();
    let mut ret = Vec::with_capacity(n);

    for i in 0..n {
        let next_bytes: Vec<u8> = [
            prefix, 
            i.to_be_bytes().to_vec().as_slice()
        ].concat();    
        let mut hasher = Sha512::new();
        hasher.update(next_bytes);
        let u = Scalar::from_hash(hasher);
        ret.push(u);
    }
    ret
}

pub fn shuffle_proof_challenge(y: &yChallengeInput, t: &tChallengeInput) -> Scalar {

    let mut bytes = concat_bytes(&y.es);
    bytes.extend(concat_bytes(&y.e_primes));
    bytes.extend(concat_bytes(&y.cs));
    bytes.extend(concat_bytes(&y.c_hats));
    bytes.extend(y.pk.0.get_bytes());
    
    bytes.extend(t.t1.get_bytes());
    bytes.extend(t.t2.get_bytes());
    bytes.extend(t.t3.get_bytes());
    bytes.extend(t.t4_1.get_bytes());
    bytes.extend(t.t4_2.get_bytes());
    bytes.extend(concat_bytes(&t.t_hats));

    let mut hasher = Sha512::new();
    hasher.update(bytes);

    return Scalar::from_hash(hasher);
}

pub fn hex(bytes: &[u8]) -> String {
    return hex::encode(bytes);
}