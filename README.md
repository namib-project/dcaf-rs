[![Crates.io](https://img.shields.io/crates/v/dcaf?style=for-the-badge&logo=rust)](https://crates.io/crates/dcaf)
[![Docs](https://img.shields.io/docsrs/dcaf?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMi00MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMi0zOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMi00MS40di0uNmwxMDItMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K)](https://docs.rs/dcaf)
[![Coverage](https://img.shields.io/coveralls/github/namib-project/dcaf-rs/main?style=for-the-badge)](https://coveralls.io/github/namib-project/dcaf-rs?branch=main)

# dcaf-rs

<!-- cargo-rdme start -->

An implementation of the [ACE-OAuth framework (RFC 9200)](https://www.rfc-editor.org/rfc/rfc9200).

This crate implements the ACE-OAuth
(Authentication and Authorization for Constrained Environments using the OAuth 2.0 Framework)
framework as defined in [RFC 9200](https://www.rfc-editor.org/rfc/rfc9200).
Key features include CBOR-(de-)serializable data models such as [`AccessTokenRequest`](https://docs.rs/dcaf/latest/dcaf/struct.AccessTokenRequest.html),
as well as the possibility to create COSE encrypted/signed access tokens
(as described in the standard) along with decryption/verification functions.
Implementations of the cryptographic functions must be provided by the user by implementing
[`EncryptCryptoBackend`](https://docs.rs/dcaf/latest/dcaf/token/cose/trait.EncryptCryptoBackend.html)
or [`SignCryptoBackend`](https://docs.rs/dcaf/latest/dcaf/token/cose/trait.SignCryptoBackend.html).

Note that actually transmitting the serialized values (e.g., via CoAP) or providing more complex
features not mentioned in the ACE-OAuth RFC (e.g., a permission management system for
the Authorization Server) is *out of scope* for this crate.
This also applies to cryptographic functions, as mentioned in the previous paragraph.

The name DCAF was chosen because eventually, it's planned for this crate to support
functionality from the [Delegated CoAP Authentication and Authorization Framework (DCAF)](https://dcaf.science/)
specified in [`draft-gerdes-ace-dcaf-authorize`](https://datatracker.ietf.org/doc/html/draft-gerdes-ace-dcaf-authorize-04)
(which was specified prior to ACE-OAuth and inspired many design choices in it)---
specifically, it's planned to support using a CAM (Client Authorization Manager)
instead of just a SAM (Server Authorization Manager), as is done in ACE-OAuth.
Compatibility with the existing [DCAF implementation in C](https://gitlab.informatik.uni-bremen.de/DCAF/dcaf)
(which we'll call `libdcaf` to disambiguate from `dcaf` referring to this crate) is also an
additional design goal, though the primary objective is still to support ACE-OAuth.

As one of the possible use-cases for this crate is usage on constrained IoT devices,
requirements are minimal---as such, while `alloc` is still needed, this crate offers
`no_std` support by omitting the default `std` feature.

## Usage
```toml
[dependencies]
dcaf = { version = "^0.4" }
```
Or, if you plan to use this crate in a `no_std` environment:
```toml
[dependencies]
dcaf = { version = "^0.4", default-features = false }
```

## Example
As mentioned, the main features of this crate are ACE-OAuth data models and
token creation/verification functions. We'll quickly introduce both of these here.

### Data models
[For example](https://www.rfc-editor.org/rfc/rfc9200#figure-6),
let's assume you (the client) want to request an access token from an Authorization Server.
For this, you'd need to create an [`AccessTokenRequest`](https://docs.rs/dcaf/latest/dcaf/struct.AccessTokenRequest.html),
which has to include at least a `client_id`. We'll also specify an audience, a scope (using
[`TextEncodedScope`](https://docs.rs/dcaf/latest/dcaf/struct.TextEncodedScope.html)---note that
[binary-encoded scopes](https://docs.rs/dcaf/latest/dcaf/struct.BinaryEncodedScope.html) or
[AIF-encoded scopes](https://docs.rs/dcaf/latest/dcaf/struct.AifEncodedScope.html) would also
work), as well as a [`ProofOfPossessionKey`](https://docs.rs/dcaf/latest/dcaf/enum.ProofOfPossessionKey.html)
(the key the access token should be bound to) in the `req_cnf` field.

Creating, serializing and then de-serializing such a structure would look like this:
```rust
use dcaf::{AccessTokenRequest, ToCborMap, ProofOfPossessionKey, TextEncodedScope};

let request = AccessTokenRequest::builder()
   .client_id("myclient")
   .audience("valve242")
   .scope(TextEncodedScope::try_from("read")?)
   .req_cnf(ProofOfPossessionKey::KeyId(hex::decode("ea483475724cd775")?))
   .build()?;
let mut encoded = Vec::new();
request.clone().serialize_into(&mut encoded)?;
assert_eq!(AccessTokenRequest::deserialize_from(encoded.as_slice())?, request);
```

### Access Tokens
Following up from the previous example, let's assume we now want to create a signed
access token containing the existing `key`, as well as claims about the audience and issuer
of the token, using the `openssl` cryptographic backend and the signing key `sign_key`:

```rust
use coset::{AsCborValue, CoseKeyBuilder, HeaderBuilder, iana};
use coset::cwt::ClaimsSetBuilder;
use coset::iana::CwtClaimName;
use dcaf::{sign_access_token, verify_access_token};
use dcaf::error::{AccessTokenError, CoseCipherError};
use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
use dcaf::token::cose::{CryptoBackend, HeaderBuilderExt};

let mut backend = OpensslContext::new();

let sign_key = CoseKeyBuilder::new_ec2_priv_key(
                            iana::EllipticCurve::P_256,
                            cose_ec2_key_x, // X component of elliptic curve key
                            cose_ec2_key_y, // Y component of elliptic curve key
                            cose_ec2_key_d  // D component of elliptic curve key
                )
                .key_id("sign_key".as_bytes().to_vec())
                .build();

let mut key_data = vec![0; 32];
backend.generate_rand(key_data.as_mut_slice()).map_err(CoseCipherError::from)?;
let key = CoseKeyBuilder::new_symmetric_key(key_data).build();

let unprotected_header = HeaderBuilder::new().algorithm(iana::Algorithm::ES256).build();

let claims = ClaimsSetBuilder::new()
     .audience(String::from("coaps://rs.example.com"))
     .issuer(String::from("coaps://as.example.com"))
     .claim(CwtClaimName::Cnf, key.clone().to_cbor_value()?)
     .build();

let token = sign_access_token(&mut backend, &key, claims, &None, Some(unprotected_header), None)?;
assert!(verify_access_token(&mut backend, &key, &token, &None).is_ok());
```

## Provided Data Models

### Token Endpoint
The most commonly used models will probably be the token endpoint's
[`AccessTokenRequest`](https://docs.rs/dcaf/latest/dcaf/struct.AccessTokenRequest.html) and
[`AccessTokenResponse`](https://docs.rs/dcaf/latest/dcaf/struct.AccessTokenResponse.html)
described in [section 5.8 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.8).
In case of an error, an [`ErrorResponse`] should be used.

After an initial Unauthorized Resource Request Message, an
[`AuthServerRequestCreationHint`](https://docs.rs/dcaf/latest/dcaf/struct.AuthServerRequestCreationHint.html)
can be used to provide additional information to the client, as described in
[section 5.3 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.3).

### Common Data Types
Some types used across multiple scenarios include:
- [`Scope`](https://docs.rs/dcaf/latest/dcaf/enum.Scope.html) (as described in
  [section 5.8.1 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.8.1)),
  either as a [`TextEncodedScope`](https://docs.rs/dcaf/latest/dcaf/struct.TextEncodedScope.html),
  a [`BinaryEncodedScope`](https://docs.rs/dcaf/latest/dcaf/struct.BinaryEncodedScope.html) or
  an [`AifEncodedScope`](https://docs.rs/dcaf/latest/dcaf/struct.AifEncodedScope.html).
- [`ProofOfPossessionKey`](https://docs.rs/dcaf/latest/dcaf/enum.ProofOfPossessionKey.html) as
  specified in [section 3.1 of RFC 8747](https://www.rfc-editor.org/rfc/rfc8747#section-3.1).
  For example, this will be used in the access token's `cnf` claim.
- While not really a data type, various constants representing values used in ACE-OAuth
  are provided in the [`constants`](https://docs.rs/dcaf/latest/dcaf/constants/index.html) module.

## Token handling

This crate also provides some functionality regarding the encoding and decoding of access
tokens, especially of CBOR Web Tokens (CWTs), which are based on the COSE specification 
(RFC 9052).

Generation and validation of CWTs is supported for CWTs based on signed and encrypted 
COSE objects. Additionally, helper methods are provided to more easily create and validate 
COSE objects that are encrypted, signed or authenticated using MACs.   

See the [token](https://docs.rs/dcaf/latest/dcaf/token/index.html) module-level documentation
for more information.

<!-- cargo-rdme end -->

## Changelog
You can find a list of changes in [CHANGELOG.md](CHANGELOG.md).

## License

Licensed under either of

* Apache License, Version 2.0
  (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license
  (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Maintainers

This project is currently maintained by the following developers:

|       Name       |    Email Address     |               GitHub Username                |
|:----------------:|:--------------------:|:--------------------------------------------:|
|  Falko Galperin  | falko1@uni-bremen.de |    [@falko17](https://github.com/falko17)    |
| Hugo Hakim Damer | hdamer@uni-bremen.de | [@pulsastrix](https://github.com/pulsastrix) |
