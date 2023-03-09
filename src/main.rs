extern crate secp256k1_zkp;

use bellman::{Circuit, ConstraintSystem, SynthesisError};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use ff::PrimeField;
//use secp256k1::{Secp256k1, SecretKey, scalar};
use secp256k1_zkp::{PedersenCommitment, Scalar, Secp256k1};




struct Secp256k1Circuit {
    pub secret_key: Scalar,
    pub public_key: secp256k1::PublicKey,
    pub message_hash: Scalar,
    pub random_nonce: Scalar,
}

impl<C: secp256k1::Context> Circuit<secp256k1::Secp256k1<C>> for Secp256k1Circuit {
    fn synthesize<CS: ConstraintSystem<secp256k1::Secp256k1<CS>> + secp256k1::Context>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Generate a Pedersen commitment to the secret key
        let pedersen_params = <secp256k1_zkp::Secp256k1<_> as Example>::pedersen::PedersenHash::new(cs.backend().public_params());
        let mut rng = ChaChaRng::seed_from_u64(123456789);
        let pedersen_commitment = PedersenCommitment::new::<CS>(
            cs.namespace(|| "Pedersen commitment to secret key"),
            &pedersen_params,
            self.secret_key.into(),
            &mut rng,
        )?;

        // Compute the public key using scalar multiplication
        let generator = Secp256k1::constants::G;
        let public_key = generator
            .mul(cs.namespace(|| "Scalar multiplication"), self.secret_key.into())
            .to_affine()
            .unwrap();

        // Verify the public key matches the known public key
        let public_key_var = secp256k1::PublicKey::new_variable(
            cs.namespace(|| "Public key"),
            &self.public_key,
            Secp256k1::Representation::Affine,
        )?;
        cs.enforce(
            || "Public key should match known public key",
            |lc| lc + public_key_var.x.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + self.public_key.x.get_variable(),
        );
        cs.enforce(
            || "Public key should match known public key",
            |lc| lc + public_key_var.y.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + self.public_key.y.get_variable(),
        );

        // Compute the nonce point using scalar multiplication
        let nonce_point = generator
            .mul(cs.namespace(|| "Scalar multiplication"), self.random_nonce.into())
            .to_affine()
            .unwrap();

        // Compute the commitment to the message hash
        let message_hash_bits = self.message_hash.to_bits_le();
        let message_bits_lc = message_hash_bits
            .iter()
            .enumerate()
            .map(|(i, bit)| {
                Ok(if *bit {
                    CS::one()
                } else {
                    CS::zero()
                } - CS::from(nonce_point.get_variable().get_lc().unwrap()[i].0.clone()))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let message_hash_commitment = PedersenCommitment::new::<CS>(
            cs.namespace(|| "Pedersen commitment to message hash"),
            &pedersen_params,
            message_bits_lc.into_iter(),
            &mut rng,
        )?;

        // Verify that the nonce point is a valid public key
        let nonce_point_var = secp256k1::PublicKey::new_variable(
            cs.namespace(|| "Nonce point"),
            &secp256k1::PublicKey::from_affine(nonce_point).unwrap(),
            Secp256k1::Representation::Affine,
        )?;
        nonce_point_var.assert_valid(cs.namespace(|| "Nonce point should be valid"))?;

        // Verify that the nonce point corresponds to the public key
        let sum_var = Secp256k1::add(
            cs.namespace(|| "Sum of public key and nonce point"),
            &public_key,
            &nonce_point_var,
        )?;
        let sum_var_x = sum_var.x;
        let public_key_var_x = public_key_var.x;
        cs.enforce(
            || "Nonce point should correspond to public key",
            |lc| lc + sum_var_x.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + public_key_var_x.get_variable(),
        );

        Ok(())
    }
}

fn main() {
    // Generate a random secret key, message hash, and nonce
    let mut rng = ChaChaRng::seed_from_u64(987654321);
    let secret_key = Scalar::random(&mut rng);
    let public_key = secp256k1::PublicKey::from_secret_key(&secret_key);
    let message_hash = Scalar::random(&mut rng);
    let random_nonce = Scalar::random(&mut rng);

    // Create a circuit instance and synthesize it
    let circuit = Secp256k1Circuit {
        secret_key,
        public_key,
        message_hash,
        random_nonce,
    };
    let prover = Secp256k1::Prover::new(&secp256k1::Secp256k1::new(), &mut rng);
    let proof = prover.prove(circuit).unwrap();

    // Verify the proof
    let verifier = Secp256k1::Verifier::new(&secp256k1::Secp256k1::new());
    assert!(verifier.verify(&proof, &[public_key], &[message_hash]).is_ok());
}
