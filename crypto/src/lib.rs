#![no_std]

#[cfg(feature = "hacspec")]
pub use edhoc_crypto_hacspec::HacspecCryptoProvider as CryptoProvider;

#[cfg(feature = "cc2538")]
pub use edhoc_crypto_cc2538::Cc2538CryptoProvider as CryptoProvider;

#[cfg(feature = "psa")]
pub use edhoc_crypto_psa::PsaCryptoProvider as CryptoProvider;
