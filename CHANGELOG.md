# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This release mainly deals with the newly released RFCs and fixes `no_std` support.

### Added

- The `CoapOscore` profile has been added as an `AceProfile`.

### Changed

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

[Unreleased]: https://github.com/olivierlacan/keep-a-changelog/compare/v0.3.1...HEAD

[AIF]: https://www.rfc-editor.org/rfc/rfc9237.html

[libdcaf]: https://gitlab.informatik.uni-bremen.de/DCAF/dcaf

[`bitflags`]: https://crates.io/crates/bitflags

[`enumflags2`]: https://crates.io/crates/enumflags2
