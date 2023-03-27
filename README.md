[![Crates.io](https://img.shields.io/crates/v/dcaf?style=for-the-badge&logo=rust)](https://crates.io/crates/dcaf)
[![Docs](https://img.shields.io/docsrs/dcaf?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMi00MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMi0zOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMi00MS40di0uNmwxMDItMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K)](https://docs.rs/dcaf)
[![Coverage](https://img.shields.io/coveralls/github/namib-project/dcaf-rs/main?style=for-the-badge)](https://coveralls.io/github/namib-project/dcaf-rs?branch=main)

# dcaf-rs

<!-- cargo-rdme start -->

An implementation of the [ACE-OAuth framework (RFC 9200)](https://www.rfc-editor.org/rfc/rfc9200).

This crate implements the ACE-OAuth
(Authentication and Authorization for Constrained Environments using the OAuth 2.0 Framework)
framework as defined in [RFC 9200](https://www.rfc-editor.org/rfc/rfc9200).
Key features include CBOR-(de-)serializable data models such as [`AccessTokenRequest`](https://docs.rs/dcaf/latest/dcaf/endpoints/token_req/struct.AccessTokenRequest.html),
as well as the possibility to create COSE encrypted/signed access tokens
(as described in the standard) along with decryption/verification functions.
Implementations of the cryptographic functions must be provided by the user by implementing
[`CoseEncryptCipher`](https://docs.rs/dcaf/latest/dcaf/token/trait.CoseEncryptCipher.html) or [`CoseSignCipher`](https://docs.rs/dcaf/latest/dcaf/token/trait.CoseSignCipher.html).

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
For this, you'd need to create an [`AccessTokenRequest`](https://docs.rs/dcaf/latest/dcaf/endpoints/token_req/struct.AccessTokenRequest.html), which has to include at least a
`client_id`. We'll also specify an audience, a scope (using [`TextEncodedScope`](https://docs.rs/dcaf/latest/dcaf/common/scope/struct.TextEncodedScope.html)---note that
[binary-encoded scopes](https://docs.rs/dcaf/latest/dcaf/common/scope/struct.BinaryEncodedScope.html) or [AIF-encoded scopes](https://docs.rs/dcaf/latest/dcaf/common/scope/struct.AifEncodedScope.html) would also work), as well as a
[`ProofOfPossessionKey`](https://docs.rs/dcaf/latest/dcaf/common/cbor_values/enum.ProofOfPossessionKey.html) (the key the access token should be bound to) in the `req_cnf` field.

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
of the token, using an existing cipher of type `FakeCrypto`[^cipher]:
```rust
use dcaf::token::CoseCipher;


let rng = FakeRng;
let key = CoseKeyBuilder::new_symmetric_key(vec![1,2,3,4,5]).key_id(vec![0xDC, 0xAF]).build();
let claims = ClaimsSetBuilder::new()
     .audience(String::from("coaps://rs.example.com"))
     .issuer(String::from("coaps://as.example.com"))
     .claim(CwtClaimName::Cnf, key.clone().to_cbor_value()?)
     .build();
let token = sign_access_token::<FakeCrypto, FakeRng>(&key, claims, None, None, None, rng)?;
assert!(verify_access_token::<FakeCrypto>(&key, &token, None).is_ok());
```

[^cipher]: Note that we are deliberately omitting details about the implementation of the
`cipher` here, since such implementations won't be in the scope of this crate.

## Provided Data Models

### Token Endpoint
The most commonly used models will probably be the token endpoint's
[`AccessTokenRequest`](https://docs.rs/dcaf/latest/dcaf/endpoints/token_req/struct.AccessTokenRequest.html) and
[`AccessTokenResponse`](https://docs.rs/dcaf/latest/dcaf/endpoints/token_req/struct.AccessTokenResponse.html)
described in [section 5.8 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.8).
In case of an error, an [`ErrorResponse`](https://docs.rs/dcaf/latest/dcaf/endpoints/token_req/struct.ErrorResponse.html)
should be used.

After an initial Unauthorized Resource Request Message, an
[`AuthServerRequestCreationHint`](https://docs.rs/dcaf/latest/dcaf/endpoints/creation_hint/struct.AuthServerRequestCreationHint.html)
can be used to provide additional information to the client, as described in
[section 5.3 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.3).

### Common Data Types
Some types used across multiple scenarios include:
- [`Scope`](https://docs.rs/dcaf/latest/dcaf/common/scope/enum.Scope.html) (as described in
  [section 5.8.1 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.8.1)),
  either as a [`TextEncodedScope`](https://docs.rs/dcaf/latest/dcaf/common/scope/struct.TextEncodedScope.html),
  a [`BinaryEncodedScope`](https://docs.rs/dcaf/latest/dcaf/common/scope/struct.BinaryEncodedScope.html) or
  an [`AifEncodedScope`](https://docs.rs/dcaf/latest/dcaf/common/scope/struct.AifEncodedScope.html).
- [`ProofOfPossessionKey`](https://docs.rs/dcaf/latest/dcaf/common/cbor_values/enum.ProofOfPossessionKey.html) as specified in
  [section 3.1 of RFC 8747](https://www.rfc-editor.org/rfc/rfc8747#section-3.1).
  For example, this will be used in the access token's `cnf` claim.
- While not really a data type, various constants representing values used in ACE-OAuth
  are provided in the [`constants`](https://docs.rs/dcaf/latest/dcaf/common/constants/) module.

## Creating Access Tokens
In order to create access tokens, you can use either [`encrypt_access_token`](https://docs.rs/dcaf/latest/dcaf/token/fn.encrypt_access_token.html)
or [`sign_access_token`](https://docs.rs/dcaf/latest/dcaf/token/fn.sign_access_token.html),
depending on whether you want the access token to be wrapped in a
`COSE_Encrypt0` or `COSE_Sign1` structure. Support for a combination of both is planned for the
future. In case you want to create a token intended for multiple recipients (each with their
own key), you can use [`encrypt_access_token_multiple`](https://docs.rs/dcaf/latest/dcaf/token/fn.encrypt_access_token_multiple.html)
or [`sign_access_token_multiple`](https://docs.rs/dcaf/latest/dcaf/token/fn.sign_access_token_multiple.html).

Both functions take a [`ClaimsSet`](coset::cwt::ClaimsSet) containing the claims that
shall be part of the access token, a key used to encrypt or sign the token,
optional `aad` (additional authenticated data), un-/protected headers and a cipher (explained
further below) identified by type parameter `T`.
Note that if the headers you pass in set fields which the cipher wants to set as well,
the function will fail with a `HeaderAlreadySet` error.
The function will return a [`Result`](https://doc.rust-lang.org/stable/core/result/enum.Result.html) of the opaque
[`ByteString`](https://docs.rs/dcaf/latest/dcaf/common/cbor_values/type.ByteString.html) containing the access token.

## Verifying and Decrypting Access Tokens
In order to verify or decrypt existing access tokens represented as [`ByteString`](https://docs.rs/dcaf/latest/dcaf/common/cbor_values/type.ByteString.html)s,
use [`verify_access_token`](https://docs.rs/dcaf/latest/dcaf/token/fn.verify_access_token.html) or
[`decrypt_access_token`](https://docs.rs/dcaf/latest/dcaf/token/fn.decrypt_access_token.html) respectively.
In case the token was created for multiple recipients (each with their own key),
use [`verify_access_token_multiple`](https://docs.rs/dcaf/latest/dcaf/token/fn.verify_access_token_multiple.html)
or [`decrypt_access_token_multiple`](https://docs.rs/dcaf/latest/dcaf/token/fn.decrypt_access_token_multiple.html).

Both functions take the access token, a `key` used to decrypt or verify, optional `aad`
(additional authenticated data) and a cipher implementing cryptographic operations identified
by type parameter `T`.

[`decrypt_access_token`](https://docs.rs/dcaf/latest/dcaf/token/fn.decrypt_access_token.html) will return a result containing
the decrypted [`ClaimsSet`](coset::cwt::ClaimsSet).
[`verify_access_token`](https://docs.rs/dcaf/latest/dcaf/token/fn.verify_access_token.html) will return an empty result which
indicates that the token was successfully verified---an [`Err`](https://doc.rust-lang.org/stable/core/result/enum.Result.html)
would indicate failure.

## Extracting Headers from an Access Token
Regardless of whether a token was signed, encrypted, or MAC-tagged, you can extract its
headers using [`get_token_headers`](https://docs.rs/dcaf/latest/dcaf/token/fn.get_token_headers.html),
which will return an option containing both
unprotected and protected headers (or which will be [`None`](core::option::Option::None) in case
the token is invalid).

## COSE Cipher
As mentioned before, cryptographic functions are outside the scope of this crate.
For this reason, the various COSE cipher traits exist; namely,
[`CoseEncryptCipher`](token::CoseEncryptCipher), [`CoseSignCipher`](token::CoseSignCipher),
and [`CoseMacCipher`](token::CoseMacCipher), each implementing
a corresponding COSE operation as specified in sections 4, 5, and 6 of
[RFC 8152](https://www.rfc-editor.org/rfc/rfc8152).
There are also the traits [`MultipleEncryptCipher`](token::MultipleEncryptCipher),
[`MultipleSignCipher`](token::MultipleSignCipher), and
[`MultipleMacCipher`](token::MultipleMacCipher),
which are used for creating tokens intended for multiple recipients.

Note that these ciphers *don't* need to wrap their results in, e.g.,
a `Cose_Encrypt0` structure, as this part is already handled by this library
(which uses [`coset`](coset))---only the cryptographic algorithms themselves need to be implemented
(e.g., step 4 of "how to decrypt a message" in [section 5.3 of RFC 8152](https://www.rfc-editor.org/rfc/rfc8152#section-5.3)).

When implementing any of the specific COSE ciphers, you'll also need to specify the type
of the key (which must be convertible to a `CoseKey`) and implement a method which sets
headers for the token, for example, the used algorithm, the key ID, an IV, and so on.

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
