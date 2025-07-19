/*
 * Copyright (c) 2024-2025 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use cfg_aliases::cfg_aliases;

fn main() {
    // Set up some aliases for conditional compilation (in order to avoid repetition).
    cfg_aliases! {
        rustcrypto_encrypt_base: {
            any(
                feature = "rustcrypto-aes-gcm",
                feature = "rustcrypto-aes-ccm",
                feature = "rustcrypto-chacha20-poly1305"
            )
        },
        rustcrypto_sign_base: {
            any(
                feature = "rustcrypto-ecdsa"
            )
        },
        rustcrypto_key_distribution_base: {
            any(
                feature = "rustcrypto-aes-kw"
            )
        },
        rustcrypto_mac_base: {
            any(
                feature = "rustcrypto-hmac",
                feature = "rustcrypto-aes-cbc-mac"
            )
        },
        rustcrypto_base: {
            any(
                rustcrypto_encrypt_base,
                rustcrypto_sign_base,
                rustcrypto_key_distribution_base,
                rustcrypto_mac_base
            )
        },
    }
}
