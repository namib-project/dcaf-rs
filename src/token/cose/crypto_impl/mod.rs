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

//! Implementations of the traits required for token handling (
//! [`CoseEncryptCipher`](crate::CoseEncryptCipher), [`CoseSignCipher`](crate::CoseSignCipher),
//! [`CoseMacCipher`](crate::CoseMacCipher)) for different cryptographic libraries.

#[cfg(feature = "openssl")]
pub mod openssl;

#[cfg(disabled)]
mod tests;
