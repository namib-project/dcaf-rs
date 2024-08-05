#![recursion_limit = "512"]

use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        rustcrypto_encrypt_base: {
            any(
                feature = "rustcrypto-aes-gcm"
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
                feature = "rustcrypto-hmac"
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
