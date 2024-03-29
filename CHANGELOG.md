# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] --- 2023-03-27

This release mainly adds support for multiple token recipients, deals with the newly released RFCs,
and fixes `no_std` support. 
Note that the cipher interfaces have been refactored in a major way.

### Added

- The `CoapOscore` profile has been added as an `AceProfile`.
- Support for multiple token recipients has been added. Specifically, the following new methods have been added:
  - `encrypt_access_token_multiple` / `decrypt_access_token_multiple`: Creates a new access token encoded as a
    `CoseEncrypt` rather than a `CoseEncrypt0`. The user passes in a vector of keys on encryption, these will then be
    used as Key Encryption Keys. The Content Encryption Key is generated by the `MultipleEncryptCipher` required by
    the function. On decryption, the correct recipient structure will be identified by the key ID of the passed-in key.
  - `sign_access_token_multiple` / `decrypt_access_token_multiple`: Creates a new access token encoded as a `CoseSign`
    rather than a `CoseSign1`. The user passes in a vector of keys when signing, and a recipient will be created
    for each key. When verifying, the correct recipient structure will be identified by the key ID of the passed-in key.

### Changed

- The ciphers' API has been majorly changed. As a result, the API for the token functions has changed as well.
  Users no longer need to pass in an instance of the cipher, they only need to specify the type parameter, as the
  cipher's methods no longer need `self` as a parameter. Additionally, users now need to pass in the `key` for the
  corresponding operation, specified as a `CoseKey`. For more information, read the
  documentation of `CoseEncryptCipher`, `CoseSignCipher`, or `CoseMacCipher`, as well as of the token functions.
- The documentation has been updated to refer to the recently released RFCs instead of the now outdated internet drafts.

### Fixed

- The crate now properly compiles in `no_std` environments, and no tests are failing. This fixes #2.
  (Contributed by @JKRhb in #3.)

## [0.3.1] --- 2022-08-11

This release adds a derived `Deserialize` trait on `AifRestMethod`.

### Added

- The trait `Deserialize` is now implemented (as a derived trait)
  on `AifRestMethod`.

### Changed

- Dependencies have been updated to their most recent version.

## [0.3.0] --- 2022-06-08

This release mainly replaces `AifRestMethodSet` (using [`bitflags`])
with `AifRestMethod` (using [`enumflags2`]).

### Changed

- The `AifRestMethodSet` (a set of REST methods) previously using
  the [`bitflags`] crate now uses the `BitFlags`
  type introduced by the [`enumflags2`] crate. `AifRestMethod`,
  a new enum whose variants can be used as parts of an
  `AifRestMethodSet` has been added too.
  The reason for this is that this makes it possible to declare
  *single* REST methods in a type-safe manner.
  - Note that any existing usages of `AifRestMethodSet` now need to
    be replaced with the new corresponding API calls.
  - Variant names are now using `PascalCase` instead of `UPPER_CASE`.
  - Use the type `AifRestMethod` for a single REST method and
    `AifRestMethodSet` for a set of REST methods.
- The `derive_builder` dependency has been updated to 0.11.2.

### Fixed

- Some incomplete documentation regarding scopes has been updated.

## [0.2.0] --- 2022-04-05

This release focuses on introducing [AIF] and [libdcaf]-support.

### Added

- Support for scopes using the
  [Authorization Information Format (AIF) for ACE](https://www.rfc-editor.org/rfc/rfc9237.html).
  For this purpose, the following types have been added:
  - `AifEncodedScope`, representing an AIF-encoded scope (surprise)
  - `AifEncodedScopeElement`, a single element in an AIF-encoded scope
    - `AifRestMethodSet`, encoding a set of REST methods
- Support for scopes used by the [libdcaf] implementation 
  (a variant of AIF-encoded scopes).

### Fixed
- Binary-encoded scopes are now properly serialized.
- Some incorrect documentation regarding scopes has been corrected.

## [0.1.0] --- 2022-04-02

As this is the first release, lots of basic functionality has been set up.
For more extensive documentation, consult the
[crate-level documentation](https://docs.rs/dcaf).

### Added
- CBOR de-/serializable model of the ACE-OAuth framework has been added:
    - Binary- and text-encoded scopes
    - Access token requests and responses
    - Authorization server request creation hints
    - Error responses
    - Various smaller types (`AceProfile`, `GrantType`, `ProofOfPossessionKey`, `TokenType`...)
    - Use `serialize_into` or `deserialize_from` to serialize and deserialize these types.
- Methods to create and work with access tokens:
    - `encrypt_access_token`
    - `decrypt_access_token`
    - `sign_access_token`
    - `verify_access_token`
    - `get_token_headers` (to extract headers from an opaque token)
- Related: Various COSE Cipher traits intended for users to implement,
  used in the above methods for cryptographic operations:
    - `CoseCipherCommon` (to set headers specific to the cipher)
    - `CoseEncrypt0Cipher`
    - `CoseVerify1Cipher`
    - `CoseMac0Cipher`
- Constants describing CBOR abbreviations of various ACE-OAuth fields
- `no_std` support

[0.1.0]: https://github.com/namib-project/dcaf-rs/releases/tag/v0.1.0

[0.2.0]: https://github.com/namib-project/dcaf-rs/compare/v0.1.0...v0.2.0

[0.3.0]: https://github.com/namib-project/dcaf-rs/compare/v0.2.0...v0.3.0

[0.3.1]: https://github.com/namib-project/dcaf-rs/compare/v0.3.0...v0.3.1

[0.3.1]: https://github.com/namib-project/dcaf-rs/compare/v0.3.1...v0.4.0

[Unreleased]: https://github.com/namib-project/dcaf-rs/compare/v0.4.0...HEAD

[AIF]: https://www.rfc-editor.org/rfc/rfc9237.html

[libdcaf]: https://gitlab.informatik.uni-bremen.de/DCAF/dcaf

[`bitflags`]: https://crates.io/crates/bitflags

[`enumflags2`]: https://crates.io/crates/enumflags2
