/*
 * Copyright (c) 2022-2024 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use crate::error::CoseCipherError;
use crate::token::cose::crypto_impl::openssl::OpensslContext;
use crate::token::cose::util::{aes_ccm_algorithm_tag_len, AES_GCM_TAG_LEN};
use crate::token::cose::{crypto_impl, CoseSymmetricKey, EncryptCryptoBackend};
use alloc::vec::Vec;
use coset::iana;
use openssl::cipher_ctx::CipherCtx;

impl EncryptCryptoBackend for OpensslContext {
    fn encrypt_aes_gcm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let cipher = crypto_impl::openssl::algorithm_to_cipher(algorithm)?;
        let mut ctx = CipherCtx::new()?;
        // So, apparently OpenSSL requires a very specific order of operations which differs
        // slightly for AES-GCM and AES-CCM in order to work.
        // It would have just been too easy if you could just generalize and reuse the code for
        // AES-CCM and AES-GCM, right?

        // Refer to https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Encryption_using_GCM_mode
        // for reference.
        // 1. First, we set the cipher.
        ctx.encrypt_init(Some(cipher), None, None)?;
        // 2. For GCM, we set the IV length _before_ setting key and IV.
        //    We do not set the tag length, as it is fixed for AES-GCM.
        ctx.set_iv_length(iv.len())?;
        // 3. Now we can set key and IV.
        ctx.encrypt_init(None, Some(key.k), Some(iv))?;
        let mut ciphertext = vec![];
        // Unlike for CCM, we *must not* set the data length here, otherwise encryption *will fail*.
        // 4. Then, we *must* set the AAD _before_ setting the plaintext.
        ctx.cipher_update(aad, None)?;
        // 5. Finally, we must provide all plaintext in a single call.
        ctx.cipher_update_vec(plaintext, &mut ciphertext)?;
        // 6. Then, we can finish the operation.
        ctx.cipher_final_vec(&mut ciphertext)?;
        let ciphertext_len = ciphertext.len();
        ciphertext.resize(ciphertext_len + AES_GCM_TAG_LEN, 0u8);
        ctx.tag(&mut ciphertext[ciphertext_len..])?;
        Ok(ciphertext)
    }

    fn decrypt_aes_gcm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let cipher = crypto_impl::openssl::algorithm_to_cipher(algorithm)?;
        let auth_tag = &ciphertext_with_tag[(ciphertext_with_tag.len() - AES_GCM_TAG_LEN)..];
        let ciphertext = &ciphertext_with_tag[..(ciphertext_with_tag.len() - AES_GCM_TAG_LEN)];

        let mut ctx = CipherCtx::new()?;
        // Refer to https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Decryption_using_GCM_mode
        // for reference.
        // 1. First, we set the cipher.
        ctx.decrypt_init(Some(cipher), None, None)?;
        // 2. For GCM, we set the IV length _before_ setting key and IV.
        //    We do not set the tag length, as it is fixed for AES-GCM.
        ctx.set_iv_length(iv.len())?;
        // 3. Now we can set key and IV.
        ctx.decrypt_init(None, Some(key.k), Some(iv))?;
        // Unlike for CCM, we *must not* set the data length here, otherwise decryption *will fail*.
        // 4. Then, we *must* set the AAD _before_ setting the ciphertext.
        ctx.cipher_update(aad, None)?;
        // 5. After that, we provide the ciphertext in a single call for decryption.
        let mut plaintext = vec![0; ciphertext.len()];
        let mut plaintext_size = ctx.cipher_update(ciphertext, Some(&mut plaintext))?;
        // 6. For GCM, we must set the tag value right before the finalization call.
        ctx.set_tag(auth_tag)?;
        // 7. Now we can finalize decryption.
        plaintext_size += ctx.cipher_final_vec(&mut plaintext)?;

        plaintext.truncate(plaintext_size);

        Ok(plaintext)
    }

    fn encrypt_aes_ccm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let cipher = crypto_impl::openssl::algorithm_to_cipher(algorithm)?;
        let tag_len = aes_ccm_algorithm_tag_len(algorithm)?;
        let mut ctx = CipherCtx::new()?;
        // Refer to https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Encryption_using_CCM_mode
        // for reference.
        // 1. First, we set the cipher.
        ctx.encrypt_init(Some(cipher), None, None)?;
        // 2. At least for CCM, we *must* set the tag and IV length _before_ setting key and IV.
        //    (https://github.com/sfackler/rust-openssl/pull/1594#issue-1105067105)
        ctx.set_iv_length(iv.len())?;
        ctx.set_tag_length(tag_len)?;
        // 3. Now we can set key and IV.
        ctx.encrypt_init(None, Some(key.k), Some(iv))?;
        let mut ciphertext = vec![];
        // 4. For CCM, we *must* then inform OpenSSL about the size of the plaintext data _before_
        //    setting the AAD.
        ctx.set_data_len(plaintext.len())?;
        // 5. Then, we *must* set the AAD _before_ setting the plaintext.
        ctx.cipher_update(aad, None)?;
        // 6. Finally, we must provide all plaintext in a single call.
        ctx.cipher_update_vec(plaintext, &mut ciphertext)?;
        // 7. Then, we can finish the operation.
        ctx.cipher_final_vec(&mut ciphertext)?;
        let ciphertext_len = ciphertext.len();
        ciphertext.resize(ciphertext_len + tag_len, 0u8);
        ctx.tag(&mut ciphertext[ciphertext_len..])?;
        Ok(ciphertext)
    }

    fn decrypt_aes_ccm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let cipher = crypto_impl::openssl::algorithm_to_cipher(algorithm)?;
        let tag_len = aes_ccm_algorithm_tag_len(algorithm)?;
        let auth_tag = &ciphertext_with_tag[(ciphertext_with_tag.len() - tag_len)..];
        let ciphertext = &ciphertext_with_tag[..(ciphertext_with_tag.len() - tag_len)];

        let mut ctx = CipherCtx::new()?;
        // Refer to https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Decryption_using_CCM_mode
        // for reference.
        // 1. First, we set the cipher.
        ctx.decrypt_init(Some(cipher), None, None)?;
        // 2. At least for CCM, we *must* set the tag and IV length _before_ setting key and IV.
        //    (https://github.com/sfackler/rust-openssl/pull/1594#issue-1105067105)
        ctx.set_iv_length(iv.len())?;
        ctx.set_tag(auth_tag)?;
        // 3. Now we can set key and IV.
        ctx.decrypt_init(None, Some(key.k), Some(iv))?;
        // 4. For CCM, we *must* then inform OpenSSL about the size of the ciphertext data _before_
        //    setting the AAD.
        ctx.set_data_len(ciphertext.len())?;
        // 5. Then, we *must* set the AAD _before_ setting the ciphertext.
        ctx.cipher_update(aad, None)?;
        // 6. Finally, we must provide all ciphertext in a single call for decryption.
        let mut plaintext = vec![0; ciphertext.len()];
        let plaintext_len = ctx.cipher_update(ciphertext, Some(&mut plaintext))?;
        plaintext.truncate(plaintext_len);
        // No call to cipher_final() here, I guess?
        // The official examples in the OpenSSL wiki don't finalize, so we won't either.

        Ok(plaintext)
    }
}
