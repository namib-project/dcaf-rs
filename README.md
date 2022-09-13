[![Crates.io](https://img.shields.io/crates/v/dcaf?style=for-the-badge&logo=rust)](https://crates.io/crates/dcaf)
[![Docs](https://img.shields.io/docsrs/dcaf?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMi00MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMi0zOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMi00MS40di0uNmwxMDItMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K)](https://docs.rs/dcaf)
[![Coverage Status](https://coveralls.io/repos/github/namib-project/dcaf-rs/badge.svg?branch=main)](https://coveralls.io/github/namib-project/dcaf-rs?branch=main)

# dcaf-rs

An implementation of the [ACE-OAuth framework](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html) in
Rust.

## Crate explanation

This crate implements the ACE-OAuth
(Authentication and Authorization for Constrained Environments using the OAuth 2.0 Framework)
framework as defined
in [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html). Key features
include CBOR-(de-)serializable data models such as `AccessTokenRequest`, as well as the possibility to create COSE
encrypted/signed access tokens
(as described in the draft) along with decryption/verification functions. Implementations of the cryptographic functions
must be provided by the user by implementing
`CoseEncrypt0Cipher` or `CoseSign1Cipher`.

Note that actually transmitting the serialized values (e.g. via CoAP) or providing more complex features not mentioned
in the ACE-OAuth Internet Draft (e.g. a permission management system for the Authorization Server) is *out of scope* for
this crate. This also applies to cryptographic functions, as mentioned in the previous paragraph.

The name DCAF was chosen because eventually, it's planned for this crate to support functionality from
the [Delegated CoAP Authentication and Authorization Framework (DCAF)](https://dcaf.science/)
specified
in [`draft-gerdes-ace-dcaf-authorize`](https://datatracker.ietf.org/doc/html/draft-gerdes-ace-dcaf-authorize-04)
(which was specified prior to ACE-OAuth and inspired many design choices in it)--- specifically, it's planned to support
using a CAM (Client Authorization Manager)
instead of just a SAM (Server Authorization Manager), as is done in ACE-OAuth. Compatibility with the
existing [DCAF implementation in C](https://gitlab.informatik.uni-bremen.de/DCAF/dcaf)
(which we'll call `libdcaf` to disambiguate from `dcaf` referring to this crate) is also an additional design goal,
though the primary objective is still to support ACE-OAuth.

As one of the possible use-cases for this crate is usage on constrained IoT devices, requirements are minimal---as such,
while `alloc` is still needed, this crate offers
`no_std` support by omitting the default `std` feature.

## Usage
```toml
[dependencies]
dcaf = { version = "^0.3" }
```
Or, if you plan to use this crate in a `no_std` environment:
```toml
[dependencies]
dcaf = { version = "^0.3", default-features = false }
```

## Example

As mentioned, the main features of this crate are ACE-OAuth data models and token creation/verification functions. We'll
quickly introduce both of these here.

### Data models

[For example](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#figure-7), say you (the client) want to
request an access token from an Authorization Server. For this, you'd need to create an `AccessTokenRequest`, which has
to include at least a
`client_id`. We'll also specify an audience, a scope (using `TextEncodedScope`---note that binary-encoded scopes
or AIF-encoded scopes would also work), as well as a
`ProofOfPossessionKey` (the key the access token should be bound to) in the `req_cnf` field.

Creating, serializing and then de-serializing such a structure would look like this:
```rust
use dcaf::{AccessTokenRequest, ToCborMap, ProofOfPossessionKey, TextEncodedScope};

let request = AccessTokenRequest::builder()
   .client_id("myclient")
   .audience("valve242")
   .scope(TextEncodedScope::try_from("read")?)
   .req_cnf(ProofOfPossessionKey::KeyId(base64::decode("6kg0dXJM13U")?))
   .build()?;
let mut encoded = Vec::new();
request.clone().serialize_into(&mut encoded)?;
assert_eq!(AccessTokenRequest::deserialize_from(encoded.as_slice())?, request);
```

### Access Tokens

Following up from the previous example, let's assume we now want to create a signed access token containing the
existing `key`, as well as claims about the audience and issuer of the token, using an existing `cipher`[^cipher]:
```rust
use dcaf::{ToCborMap, sign_access_token, verify_access_token};
use coset::cwt::ClaimsSetBuilder;
use coset::Header;
use coset::iana::CwtClaimName;

let claims = ClaimsSetBuilder::new()
   .audience("valve242".to_string())
   .claim(CwtClaimName::Cnf, key.to_ciborium_value())
   .claim(CwtClaimName::Scope, Value::Text("read".to_string()))
   .build();
let token = sign_access_token(claims, &mut cipher, None, None, None)?;
assert!(verify_access_token(&token, &mut cipher, None).is_ok());
```

[^cipher]: Note that we are deliberately omitting details about the implementation of the
`cipher` here, since such implementations won't be in scope of this crate.

## Provided Data Models

### Token Endpoint

The most commonly used models will probably be the token endpoint's `AccessTokenRequest` and
`AccessTokenResponse` described in
[section 5.8 of the ACE-OAuth draft](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.8). In
case of an error, an `ErrorResponse` should be used.

After an initial Unauthorized Resource Request Message, an `AuthServerRequestCreationHint` can be used to provide
additional information to the client, as described in
[section 5.3 of the ACE-OAuth draft](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.3).

### Common Data Types
Some types used across multiple scenarios include:

- `Scope` (as described
  in [section 5.8.1 of the ACE-OAuth draft](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.8.1))
  , either as a `TextEncodedScope`, a `BinaryEncodedScope` or an `AifEncodedScope`.
- `ProofOfPossessionKey` as specified
  in [section 3.1 of RFC 8747](https://datatracker.ietf.org/doc/html/rfc8747#section-3.1). For example, this will be
  used in the access token's `cnf` claim.
- While not really a data type, various constants representing values used in ACE-OAuth are provided in the `constants`
  module.

## Creating Access Tokens

In order to create access tokens, you can use either `encrypt_access_token` or
`sign_access_token`, depending on whether you want the access token to be wrapped in a
`COSE_Encrypt0` or `COSE_Sign1` structure. Support for a combination of both is planned for the future.

Both functions take a `ClaimsSet` containing the claims that shall be part of the access token, a cipher implementing
the cryptographic operations
(explained further below), as well as optional `aad` (additional authenticated data)
and un-/protected headers. Note that if the headers you pass in set fields which the cipher wants to set as well, the
function will fail with a
`HeaderAlreadySet` error. The function will return a `Result` of the opaque `ByteString` containing the access token.

## Verifying / decrypting Access Tokens

In order to verify or decrypt existing access tokens represented as `ByteString`s, use `verify_access_token`
or `decrypt_access_token` respectively.

Both functions take the access token, a `cipher` for the cryptographic operations and an optional `aad` (additional
authenticated data).

`decrypt_access_token` will return a result containing the decrypted
`ClaimsSet`.
`verify_access_token` will return an empty result which indicates that the token was successfully verified---an `Err`
would indicate failure.

## Extracting Headers from an Access Token

Regardless of whether token was signed, encrypted, or MAC-tagged, you can extract its headers using `get_token_headers`,
which will return an option containing both unprotected and protected headers (or which will be `None` in case the token
is invalid or neither a `COSE_Sign1`, `COSE_Encrypt0`, or `COSE_Mac0` structure).

## COSE Cipher

As mentioned before, cryptographic functions are outside the scope of this crate. For this reason, the various COSE
cipher traits exist; namely,
`CoseEncrypt0Cipher`, `CoseSign1Cipher`, and `CoseMac0Cipher`, each implementing a corresponding COSE operation as
specified in sections 4, 5, and 6 of
[RFC 8152](https://datatracker.ietf.org/doc/html/rfc8152).

Note that these ciphers *don't* need to wrap their results in e.g. a `Cose_Encrypt0` structure, this part is already
handled using this library (which uses `coset`)---only the cryptographic algorithms themselves need to be implemented
(e.g. step 4 of
"how to decrypt a message" in [section 5.3 of RFC 8152](https://datatracker.ietf.org/doc/html/rfc8152#section-5.3)).

When implementing any of the specific COSE ciphers, you'll also need to implement the
`CoseCipherCommon` trait, which can be used to set headers specific to your COSE cipher
(e.g. the used algorithm).

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
