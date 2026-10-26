/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

//! Bridge the existing public RNG contract without copying or reseeding its state.

use core::convert::Infallible;

use rand_core::CryptoRngCore;
use rand_core_10::{TryCryptoRng, TryRng};

pub(super) struct RngCompat<'a, R: ?Sized>(&'a mut R);

impl<'a, R: CryptoRngCore + ?Sized> RngCompat<'a, R> {
    pub(super) fn new(rng: &'a mut R) -> Self {
        Self(rng)
    }
}

impl<R: CryptoRngCore + ?Sized> TryRng for RngCompat<'_, R> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        // Match the old RustCrypto calls' infallible API: entropy failures must
        // propagate as panics, never be discarded or replaced with other bytes.
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<R: CryptoRngCore + ?Sized> TryCryptoRng for RngCompat<'_, R> {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{CryptoRng, RngCore};

    struct SequenceRng(u8);

    impl RngCore for SequenceRng {
        fn next_u32(&mut self) -> u32 {
            self.0 += 1;
            u32::from(self.0)
        }

        fn next_u64(&mut self) -> u64 {
            self.0 += 1;
            u64::from(self.0)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                self.0 += 1;
                *byte = self.0;
            }
        }

        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
            panic!("the old infallible API must be forwarded")
        }
    }

    impl CryptoRng for SequenceRng {}

    #[test]
    fn generated_secret_key_retries_zero_and_remains_reloadable() {
        use super::super::RustCrypto;
        use crate::crypto::{CanonPkcSecretKey, CanonPkcSecretKeyRef, Crypto, SecretKey};

        struct ZeroThenOne(usize);
        impl RngCore for ZeroThenOne {
            fn next_u32(&mut self) -> u32 {
                panic!("unexpected word request")
            }
            fn next_u64(&mut self) -> u64 {
                panic!("unexpected word request")
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                dest.fill(if self.0 == 0 { 0 } else { 1 });
                self.0 += 1;
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }
        impl CryptoRng for ZeroThenOne {}

        let singleton = [1; 32];
        let crypto = RustCrypto::new(ZeroThenOne(0), CanonPkcSecretKeyRef::new(&singleton));
        let key = crypto.generate_secret_key().unwrap();
        let mut bytes = CanonPkcSecretKey::new();
        key.write_canon(&mut bytes).unwrap();
        assert!(bytes.access().iter().any(|byte| *byte != 0));
        crypto.secret_key(bytes.reference()).unwrap();
    }

    #[test]
    fn existing_public_rng_supports_key_scalar_signature_and_csr_roundtrips() {
        use super::super::RustCrypto;
        use crate::cert::x509::csr::CsrRef;
        use crate::crypto::{
            CanonEcScalar, CanonPkcPublicKey, CanonPkcSecretKey, CanonPkcSecretKeyRef,
            CanonPkcSharedSecret, CanonPkcSignature, Crypto, EcScalar, PublicKey, SecretKey,
            SigningSecretKey, WeakTestOnlyRand,
        };

        let singleton = [1; 32];
        let crypto = RustCrypto::new(
            WeakTestOnlyRand::new_default(),
            CanonPkcSecretKeyRef::new(&singleton),
        );
        let key = crypto.generate_secret_key().unwrap();
        let mut persisted_key = CanonPkcSecretKey::new();
        key.write_canon(&mut persisted_key).unwrap();
        let restored = crypto.secret_key(persisted_key.reference()).unwrap();
        let public_key = restored.pub_key().unwrap();
        let mut signature = CanonPkcSignature::new();
        restored.sign(b"old RNG contract", &mut signature).unwrap();
        public_key
            .verify(b"old RNG contract", signature.reference())
            .unwrap();

        let mut csr_buffer = [0; 1024];
        let csr = CsrRef::new(restored.csr(&mut csr_buffer).unwrap()).unwrap();
        csr.verify(&crypto).unwrap();
        let mut public_bytes = CanonPkcPublicKey::new();
        public_key.write_canon(&mut public_bytes).unwrap();
        assert!(csr.pubkey().unwrap().as_slice() == public_bytes.access());

        let peer = crypto.generate_secret_key().unwrap();
        let mut left = CanonPkcSharedSecret::new();
        let mut right = CanonPkcSharedSecret::new();
        restored
            .derive_shared_secret(&peer.pub_key().unwrap(), &mut left)
            .unwrap();
        peer.derive_shared_secret(&public_key, &mut right).unwrap();
        assert!(left.access() == right.access());

        let scalar = crypto.generate_ec_scalar().unwrap();
        let mut scalar_bytes = CanonEcScalar::new();
        scalar.write_canon(&mut scalar_bytes).unwrap();
        crypto.ec_scalar(scalar_bytes.reference()).unwrap();
    }

    #[test]
    fn forwards_calls_without_copying_or_restarting_the_old_rng() {
        let mut old = SequenceRng(0);
        let mut bytes = [0; 3];
        {
            let mut rng = RngCompat::new(&mut old);
            assert_eq!(rng.try_next_u32(), Ok(1));
            assert_eq!(rng.try_next_u64(), Ok(2));
            assert_eq!(rng.try_fill_bytes(&mut bytes), Ok(()));
            assert_eq!(bytes, [3, 4, 5]);
        }
        assert_eq!(old.next_u32(), 6);
        assert_eq!(RngCompat::new(&mut old).try_next_u64(), Ok(7));
    }

    #[test]
    #[should_panic(expected = "old entropy source failed")]
    fn old_entropy_failure_is_not_silently_converted_to_success() {
        struct FailedRng;
        impl RngCore for FailedRng {
            fn next_u32(&mut self) -> u32 {
                panic!("old entropy source failed")
            }
            fn next_u64(&mut self) -> u64 {
                panic!("old entropy source failed")
            }
            fn fill_bytes(&mut self, _: &mut [u8]) {
                panic!("old entropy source failed")
            }
            fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
                panic!("the infallible path must be used")
            }
        }
        impl CryptoRng for FailedRng {}
        let _ = RngCompat::new(&mut FailedRng).try_fill_bytes(&mut [0; 32]);
    }
}
