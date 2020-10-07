use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT, BASEPOINT_ORDER};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct Ciphertext {
    pub a: RistrettoPoint,
    pub b: RistrettoPoint
}

/* fn encode_u32(message: &u32) -> CompressedRistretto {
    let bytes = bincode::serialize(message).unwrap();
    
    println!("encode_u32: {:?}", bytes);
    return CompressedRistretto::from_slice(bytes.as_slice());
    
}

fn decode_u32(point: CompressedRistretto) -> u32 {
    let bytes = point.as_bytes();
    let integer: u32 = bincode::deserialize(bytes).unwrap();
    
    println!("decode_u32: {:?}", bytes);
    return integer;
    
}*/

pub struct PublicKey(pub RistrettoPoint);

impl PublicKey {
    pub fn encrypt<T: RngCore + CryptoRng>(&self, plaintext: RistrettoPoint, csprng: &mut T) -> Ciphertext {
        let randomness = Scalar::random(csprng);
        Ciphertext {
            a: plaintext + (self.0 * randomness),
            b: RISTRETTO_BASEPOINT_POINT * randomness
        }
    }
}

pub struct PrivateKey(Scalar);

impl PrivateKey {
    pub fn random<T: RngCore + CryptoRng>(csprng: &mut T) -> Self {
        return PrivateKey(Scalar::random(csprng));
    }
    pub fn public_key(&self) -> PublicKey {
        return PublicKey(RISTRETTO_BASEPOINT_POINT * self.0);
    }
    pub fn decrypt(&self, c: Ciphertext) -> RistrettoPoint {
        // c.b - (c.a * self.0)
        c.a - (c.b * self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encryption() {
        let mut csprng = OsRng;
        let sk = PrivateKey::random(&mut csprng);
        
        let pk = sk.public_key();
        let text = "this has to be exactly 32 bytes!";
        let plaintext = CompressedRistretto::from_slice(text.as_bytes());    
        
        let c: Ciphertext = pk.encrypt(plaintext.decompress().unwrap(), &mut csprng);
        let d: RistrettoPoint = sk.decrypt(c);
        
        let recovered = String::from_utf8(d.compress().as_bytes().to_vec());
        assert_eq!(text, recovered.unwrap());
    }
}