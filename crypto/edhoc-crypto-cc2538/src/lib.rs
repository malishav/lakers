#![no_std]

use edhoc_consts::*;

use cc2538_hal::crypto::aes_engine::ccm::AesCcmInfo;
use cc2538_hal::crypto::aes_engine::keys::{AesKey, AesKeySize, AesKeys};
use cc2538_hal::crypto::ecc::EcPoint;
use cc2538_hal::crypto::ecc::EccCurveInfo;
use cc2538_hal::crypto::Crypto;

pub struct Cc2538CryptoProvider<'a> {
    crypto: Crypto<'a>,
}

impl<'a> Cc2538CryptoProvider<'a> {
    pub fn new(crypto: Crypto<'a>) -> Self {
        Self { crypto }
    }

    pub fn sha256_digest(&self, message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen {
        BytesHashLen::new()
    }

    pub fn hkdf_expand(
        &self,
        prk: &BytesHashLen,
        info: &BytesMaxInfoBuffer,
        info_len: usize,
        length: usize,
    ) -> BytesMaxBuffer {
        BytesMaxBuffer::new()
    }

    pub fn hkdf_extract(&self, salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
        BytesHashLen::new()
    }

    pub fn aes_ccm_encrypt_tag_8(
        &self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &BytesEncStructureLen,
        plaintext: &BytesPlaintext3,
    ) -> BytesCiphertext3 {
        BytesCiphertext3::new()
    }

    pub fn aes_ccm_decrypt_tag_8(
        &self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &BytesEncStructureLen,
        ciphertext: &BytesCiphertext3,
    ) -> (EDHOCError, BytesPlaintext3) {
        (EDHOCError::Success, BytesPlaintext3::new())
    }
    pub fn p256_ecdh(
        &self,
        private_key: &BytesP256ElemLen,
        public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen {
        BytesP256ElemLen::new()
    }
}
