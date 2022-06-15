use hacspec_lib::*;

bytes!(Bytes1, 1);
bytes!(Bytes3, 3);
bytes!(Bytes32, 32);
bytes!(BytesP256ElemLen, 32);
bytes!(Bytes83, 83);

pub const I: Bytes32 = Bytes32(secret_bytes!([
    0xfb, 0x13, 0xad, 0xeb, 0x65, 0x18, 0xce, 0xe5, 0xf8, 0x84, 0x17, 0x66, 0x08, 0x41, 0x14, 0x2e,
    0x83, 0x0a, 0x81, 0xfe, 0x33, 0x43, 0x80, 0xa9, 0x53, 0x40, 0x6a, 0x13, 0x05, 0xe8, 0x70, 0x6b
]));

pub const ID_CRED_R: Bytes3 = Bytes3(secret_bytes!([0xA1, 0x04, 0x05]));
pub const CRED_R: Bytes83 = Bytes83(secret_bytes!([
    0xA2, 0x02, 0x60, 0x08, 0xA1, 0x01, 0xA5, 0x01, 0x02, 0x02, 0x05, 0x20, 0x01, 0x21, 0x58, 0x20,
    0x6F, 0x97, 0x02, 0xA6, 0x66, 0x02, 0xD7, 0x8F, 0x5E, 0x81, 0xBA, 0xC1, 0xE0, 0xAF, 0x01, 0xF8,
    0xB5, 0x28, 0x10, 0xC5, 0x02, 0xE8, 0x7E, 0xBB, 0x7C, 0x92, 0x6C, 0x07, 0x42, 0x6F, 0xD0, 0x2F,
    0x22, 0x58, 0x20, 0xC8, 0xD3, 0x32, 0x74, 0xC7, 0x1C, 0x9B, 0x3E, 0xE5, 0x7D, 0x84, 0x2B, 0xBF,
    0x22, 0x38, 0xB8, 0x28, 0x3C, 0xB4, 0x10, 0xEC, 0xA2, 0x16, 0xFB, 0x72, 0xA7, 0x8E, 0xA7, 0xA8,
    0x70, 0xF8, 0x00
]));
pub const G_R: Bytes32 = Bytes32(secret_bytes!([
    0x6f, 0x97, 0x02, 0xa6, 0x66, 0x02, 0xd7, 0x8f, 0x5e, 0x81, 0xba, 0xc1, 0xe0, 0xaf, 0x01, 0xf8,
    0xb5, 0x28, 0x10, 0xc5, 0x02, 0xe8, 0x7e, 0xbb, 0x7c, 0x92, 0x6c, 0x07, 0x42, 0x6f, 0xd0, 0x2f
]));

pub const C_I: i8 = -24;
pub const G_X: BytesP256ElemLen = BytesP256ElemLen(secret_bytes!([
    0x8a, 0xf6, 0xf4, 0x30, 0xeb, 0xe1, 0x8d, 0x34, 0x18, 0x40, 0x17, 0xa9, 0xa1, 0x1b, 0xf5, 0x11,
    0xc8, 0xdf, 0xf8, 0xf8, 0x34, 0x73, 0x0b, 0x96, 0xc1, 0xb7, 0xc8, 0xdb, 0xca, 0x2f, 0xc3, 0xb6
]));
pub const X: BytesP256ElemLen = BytesP256ElemLen(secret_bytes!([
    0x36, 0x8e, 0xc1, 0xf6, 0x9a, 0xeb, 0x65, 0x9b, 0xa3, 0x7d, 0x5a, 0x8d, 0x45, 0xb2, 0x1b, 0xdc,
    0x02, 0x99, 0xdc, 0xea, 0xa8, 0xef, 0x23, 0x5f, 0x3c, 0xa4, 0x2c, 0xe3, 0x53, 0x0f, 0x95, 0x25
]));
pub const MESSAGE_2_LEN: usize = 45;
pub const MESSAGE_3_LEN: usize = CIPHERTEXT_3_LEN + 1; // 1 to wrap ciphertext into a cbor byte string
pub const EDHOC_METHOD: u8 = 3; // stat-stat is the only supported method
pub const EDHOC_SUPPORTED_SUITES: Bytes1 = Bytes1(secret_bytes!([0x2]));
pub const P256_ELEM_LEN: usize = 32;
pub const SHA256_DIGEST_LEN: usize = 32;
pub const AES_CCM_KEY_LEN: usize = 16;
pub const AES_CCM_IV_LEN: usize = 13;
pub const AES_CCM_TAG_LEN: usize = 8;
pub const MAC_LENGTH_2: usize = 8;
pub const MAC_LENGTH_3: usize = MAC_LENGTH_2;
// ciphertext is message_len -1 for c_r, -2 for cbor magic numbers
pub const CIPHERTEXT_2_LEN: usize = MESSAGE_2_LEN - P256_ELEM_LEN - 1 - 2;
pub const PLAINTEXT_2_LEN: usize = CIPHERTEXT_2_LEN;
pub const PLAINTEXT_3_LEN: usize = MAC_LENGTH_3 + 2; // support for kid auth only
pub const CIPHERTEXT_3_LEN: usize = PLAINTEXT_3_LEN + AES_CCM_TAG_LEN;

// maximum supported length of connection identifier for R
pub const MAX_KDF_CONTEXT_LEN: usize = 120;
pub const MAX_KDF_LABEL_LEN: usize = 15; // for "KEYSTREAM_2"
pub const MAX_BUFFER_LEN: usize = 150;
pub const CBOR_BYTE_STRING: u8 = 0x58;
pub const CBOR_MAJOR_TEXT_STRING: u8 = 0x60;
pub const CBOR_MAJOR_BYTE_STRING: u8 = 0x40;
pub const CBOR_MAJOR_ARRAY: u8 = 0x80;
