/*
 * Copyright (c) 2022 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Contains data types and methods for working with OAuth scopes.
//!
//! The main use case of this module is creating [Scope] instances for either text-,
//! binary-, or AIF-encoded scopes,
//! whose elements can then be extracted using the `elements()` method.
//!
//! # Example
//! For example, you could first create a text-, binary-, or AIF-encoded scope:
//! ```
//! # use std::error::Error;
//! # use dcaf::common::scope::{AifEncodedScopeElement, AifRestMethod, AifRestMethodSet, BinaryEncodedScope, TextEncodedScope};
//! # use dcaf::error::{InvalidBinaryEncodedScopeError, InvalidTextEncodedScopeError};
//! # use dcaf::{AifEncodedScope, Scope};
//! // Will be encoded with a space-separator.
//! # #[cfg(feature = "std")] {
//! let text_scope = TextEncodedScope::try_from(vec!["first_client", "second_client"])?;
//! assert_eq!(text_scope.to_string(), "first_client second_client");
//! assert!(text_scope.elements().eq(vec!["first_client", "second_client"]));
//!
//! // Separator is only specified upon `elements` call.
//! let binary_scope = BinaryEncodedScope::try_from(vec![1, 2, 0, 3, 4].as_slice())?;
//! assert!(binary_scope.elements(Some(0))?.eq(&vec![&vec![1, 2], &vec![3, 4]]));
//! # }
//!
//! // Will be encoded as path and REST-method-set pairs.
//! let aif_scope = AifEncodedScope::from(vec![
//!    ("/s/temp", AifRestMethod::Get.into()), ("/none", AifRestMethodSet::empty())
//! ]);
//! assert_eq!(aif_scope.elements(), &vec![
//!    AifEncodedScopeElement::new("/s/temp", AifRestMethod::Get),
//!    AifEncodedScopeElement::new("/none", AifRestMethodSet::empty())
//! ]);
//! # Ok::<(), Box<dyn Error>>(())
//! ```
//! And then you could wrap it in the [Scope] type and use it in a field,
//! e.g. in an [`AuthServerRequestCreationHint`](crate::AuthServerRequestCreationHint):
//! ```
//! # use std::error::Error;
//! # use dcaf::common::scope::{BinaryEncodedScope, TextEncodedScope};
//! # use dcaf::{AuthServerRequestCreationHint, Scope};
//! # use dcaf::endpoints::creation_hint::AuthServerRequestCreationHintBuilderError;
//! # #[cfg(feature = "std")] {
//! # let text_scope = TextEncodedScope::try_from(vec!["first_client", "second_client"])?;
//! # let original_scope = text_scope.clone();
//! # let binary_scope = BinaryEncodedScope::try_from(vec![1, 2, 0, 3, 4].as_slice())?;
//! let hint: AuthServerRequestCreationHint = AuthServerRequestCreationHint::builder().scope(Scope::from(text_scope)).build()?;
//! # assert_eq!(hint.scope, Some(Scope::from(original_scope)));
//! # }
//! # Ok::<(), Box<dyn Error>>(())
//! ```
//! This works with the binary encoded scope too, of course:
//! ```
//! # use std::error::Error;
//! # use dcaf::common::scope::{BinaryEncodedScope, TextEncodedScope};
//! # use dcaf::{AuthServerRequestCreationHint, Scope};
//! # use dcaf::endpoints::creation_hint::AuthServerRequestCreationHintBuilderError;
//! # #[cfg(feature = "std")] {
//! # let binary_scope = BinaryEncodedScope::try_from(vec![1, 2, 0, 3, 4].as_slice())?;
//! # let original_scope = binary_scope.clone();
//! let hint: AuthServerRequestCreationHint = AuthServerRequestCreationHint::builder().scope(Scope::from(binary_scope)).build()?;
//! # assert_eq!(hint.scope, Some(Scope::from(original_scope)));
//! # }
//! # Ok::<(), Box<dyn Error>>(())
//! ```
//! As well as with the AIF-encoded scope:
//! ```
//! # use std::error::Error;
//! # use dcaf::common::scope::{AifEncodedScope, AifRestMethod, AifRestMethodSet};
//! # use dcaf::{AuthServerRequestCreationHint, Scope};
//! # use dcaf::endpoints::creation_hint::AuthServerRequestCreationHintBuilderError;
//! # let aif_scope = AifEncodedScope::from(vec![
//! #    ("/s/temp", AifRestMethod::Get.into()), ("/none", AifRestMethodSet::empty())
//! # ]);
//! # let original_scope = aif_scope.clone();
//! # #[cfg(feature = "std")] {
//! let hint: AuthServerRequestCreationHint = AuthServerRequestCreationHint::builder().scope(Scope::from(aif_scope)).build()?;
//! # assert_eq!(hint.scope, Some(Scope::from(original_scope)));
//! # }
//! # Ok::<(), Box<dyn Error>>(())
//! ```
//!
//! # Sources
//! For the original OAuth 2.0 standard, scopes are defined in
//! [RFC 6749, section 1.3](https://www.rfc-editor.org/rfc/rfc6749#section-1.3),
//! while for ACE-OAuth, they're specified in
//! [RFC 9200, section 5.8.1](https://www.rfc-editor.org/rfc/rfc9200#section-5.8.1-2.4).
//! AIF is defined in [RFC 9237](https://www.rfc-editor.org/rfc/rfc9237).

#[cfg(not(feature = "std"))]
use {alloc::string::String, alloc::string::ToString, alloc::vec, alloc::vec::Vec};

use core::fmt::{Display, Formatter};

use enumflags2::{bitflags, BitFlags};
use serde::{Deserialize, Serialize};
use strum_macros::IntoStaticStr;

use crate::common::cbor_values::ByteString;

#[cfg(test)]
mod tests;

/// A set of [`AifRestMethod`]s, represented as bitflags.
/// Intended to be used in [`AifEncodedScope`]s.
///
/// In order to create an instance of this type, simply do one of the following things:
/// ```
/// # use std::error::Error;
/// # use enumflags2::make_bitflags;
/// # use dcaf::common::scope::{AifRestMethod, AifRestMethodSet};
/// // By bitwise operators:
/// let multiple_or: AifRestMethodSet = AifRestMethod::Get | AifRestMethod::Put;
/// assert!(multiple_or.contains(AifRestMethod::Get) && multiple_or.contains(AifRestMethod::Put));
/// # assert_eq!(multiple_or.len(), 2);
/// // By the `make_bitflags` macro, to be more compact:
/// let multiple_macro: AifRestMethodSet = make_bitflags!(AifRestMethod::{Get | Put});
/// assert!(multiple_macro.contains(AifRestMethod::Get | AifRestMethod::Put));
/// # assert_eq!(multiple_macro.len(), 2);
/// // Or by the methods defined on `AifRestMethodSet`:
/// let single = AifRestMethodSet::try_from(AifRestMethod::Get)?;
/// assert!(single.exactly_one().filter(|x| x == &AifRestMethod::Get).is_some());
/// let empty = AifRestMethodSet::empty();
/// assert!(empty.is_empty());
/// let all = AifRestMethodSet::all();
/// assert!(all.is_all());
/// # Ok::<(), Box<dyn Error>>(())
/// ```
pub type AifRestMethodSet = BitFlags<AifRestMethod>;

/// A scope encoded as a space-delimited list of strings, as defined in
/// [RFC 6749, section 1.3](https://www.rfc-editor.org/rfc/rfc6749#section-1.3).
///
/// Note that the syntax specified in the RFC has to be followed:
/// ```text
/// scope       = scope-token *( SP scope-token )
/// scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
/// ```
///
/// # Example
///
/// You can create a `TextEncodedScope` from a space-separated string:
/// ```
/// # use dcaf::common::scope::TextEncodedScope;
/// # use dcaf::error::InvalidTextEncodedScopeError;
/// let scope = TextEncodedScope::try_from("first second third")?;
/// assert!(scope.elements().eq(["first", "second", "third"]));
/// # Ok::<(), InvalidTextEncodedScopeError>(())
/// ```
/// It's also possible to pass in a vector of strings:
/// ```
/// # use dcaf::common::scope::TextEncodedScope;
/// # use dcaf::error::InvalidTextEncodedScopeError;
/// let scope = TextEncodedScope::try_from(vec!["first", "second", "third"])?;
/// assert!(scope.elements().eq(["first", "second", "third"]));
/// assert!(TextEncodedScope::try_from(vec!["not allowed"]).is_err());
/// # Ok::<(), InvalidTextEncodedScopeError>(())
/// ```
///
/// But note that you have to follow the syntax from the RFC (which implicitly specifies
/// that given scopes can't be empty):
/// ```
/// # use dcaf::common::scope::TextEncodedScope;
/// assert!(TextEncodedScope::try_from("can't use \\ or \"").is_err());
/// assert!(TextEncodedScope::try_from("  no   weird spaces ").is_err());
/// assert!(TextEncodedScope::try_from(vec![]).is_err());
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize)]
pub struct TextEncodedScope(String);

impl Display for TextEncodedScope {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A scope encoded using a custom binary encoding.
/// See [Scope] for more information.
///
/// # Example
///
/// Simply create a `BinaryEncodedScope` from a byte array (we're using the byte `0x21` as
/// a separator in this example):
/// ```
/// # use dcaf::common::scope::{BinaryEncodedScope};
/// # use dcaf::error::InvalidBinaryEncodedScopeError;
/// let scope = BinaryEncodedScope::try_from(vec![0x00, 0x21, 0xDC, 0xAF].as_slice())?;
/// assert!(scope.elements(Some(0x21))?.eq(&vec![vec![0x00], vec![0xDC, 0xAF]]));
/// # Ok::<(), InvalidBinaryEncodedScopeError>(())
/// ```
///
/// But note that the input array can't be empty:
/// ```
/// # use dcaf::common::scope::BinaryEncodedScope;
/// assert!(BinaryEncodedScope::try_from(vec![].as_slice()).is_err());
/// ```
///
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize)]
pub struct BinaryEncodedScope(ByteString);

/// REST (CoAP or HTTP) methods, intended for use in an [`AifEncodedScopeElement`].
///
/// In order to create a bitmask, simply use one of the following on an enum variant:
/// - bitwise operators (e.g., `AifRestMethod::Get | AifRestMethod::Put`)
/// - `make_bitflags` macro (e.g., `make_bitflags!(AifRestMethod::{Get,Put})`)
/// - `From` implementations (e.g., `AifRestMethod::Get.into()`)
///
/// Note that in addition to the usual CoAP and HTTP REST methods
/// (see "Relevant Documents" below),
/// methods for [Dynamic Resource Creation](https://www.rfc-editor.org/rfc/rfc9237#section-2.3)
/// are also provided.
///
/// This uses the [`enumflags2`] crate to make it easy to work with resulting bitmasks.
///
/// # Relevant Documents
/// - Definition of `REST-method-set` data model for use in AIF:
///   Figure 4 of [RFC 9237](https://www.rfc-editor.org/rfc/rfc9237#figure-4)
/// - Specification of HTTP methods GET, POST, PUT, DELETE: [RFC 7231, section 4.3](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3)
/// - Specification of HTTP PATCH method: [RFC 5789](https://datatracker.ietf.org/doc/html/rfc5789)
/// - Specification of CoAP methods GET, POST, PUT, DELETE: [RFC 7252, section 5.8](https://datatracker.ietf.org/doc/html/rfc7252#section-5.8),
/// - Specification of CoAP methods FETCH, PATCH, AND iPATCH: [RFC 8132](https://datatracker.ietf.org/doc/html/rfc8132)
/// - Specification of Dynamic CoAP methods:
///   [RFC 9237, section 2.3](https://www.rfc-editor.org/rfc/rfc9237#section-2.3)
///
/// # Example
/// You can easily combine multiple fields using the bitwise OR operator, as well as
/// using the built-in methods from [`enumflags2`].
/// Created bitmasks can then be used in an [AifEncodedScopeElement]:
/// ```
/// # use dcaf::AifEncodedScope;
/// # use dcaf::common::scope::{AifEncodedScopeElement, AifRestMethod, AifRestMethodSet};
/// let get = AifEncodedScopeElement::new("restricted", AifRestMethod::Get);
/// let multiple = AifEncodedScopeElement::new("less_restricted",
///                                            AifRestMethod::Get | AifRestMethod::Fetch);
/// // GET equals 2^0, FETCH equals 2^4
/// assert_eq!(multiple.permissions.bits(), 0b1 | 0b10000);
/// let all = AifEncodedScopeElement::new("unrestricted", AifRestMethodSet::all());
/// ```
/// These elements can in turn be used in an [AifEncodedScope] (or [LibdcafEncodedScope]):
/// ```
/// # use dcaf::AifEncodedScope;
/// # use dcaf::common::scope::{AifEncodedScopeElement, AifRestMethod, AifRestMethodSet};
/// # let get = AifEncodedScopeElement::new("restricted", AifRestMethod::Get);
/// # let multiple = AifEncodedScopeElement::new("less_restricted",
/// #                                            AifRestMethod::Get | AifRestMethod::Fetch);
/// # let all = AifEncodedScopeElement::new("unrestricted", AifRestMethodSet::all());
/// let scope = AifEncodedScope::new(vec![get, multiple, all]);
/// ```
#[bitflags]
#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[repr(u64)]
pub enum AifRestMethod {
    /// GET method as specified in [RFC 7252, section 5.8.1 (CoAP)](https://datatracker.ietf.org/doc/html/rfc7252#section-5.8.1)
    /// and [RFC 7231, section 4.3.1 (HTTP)](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.1).
    Get = u64::pow(2, 0),

    /// POST method as specified in [RFC 7252, section 5.8.2 (CoAP)](https://datatracker.ietf.org/doc/html/rfc7252#section-5.8.2)
    /// and [RFC 7231, section 4.3.3 (HTTP)](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.3).
    Post = u64::pow(2, 1),

    /// PUT method as specified in [RFC 7252, section 5.8.3 (CoAP)](https://datatracker.ietf.org/doc/html/rfc7252#section-5.8.3)
    /// and [RFC 7231, section 4.3.4 (HTTP)](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.4).
    Put = u64::pow(2, 2),

    /// DELETE method as specified in [RFC 7252, section 5.8.4 (CoAP)](https://datatracker.ietf.org/doc/html/rfc7252#section-5.8.4)
    /// and [RFC 7231, section 4.3.5 (HTTP)](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.5).
    Delete = u64::pow(2, 3),

    /// FETCH method as specified in [RFC 8132, section 2 (CoAP)](https://datatracker.ietf.org/doc/html/rfc8132#section-2).
    ///
    /// Not available for HTTP.
    Fetch = u64::pow(2, 4),

    /// PATCH method as specified in [RFC 8132, section 3 (CoAP)](https://datatracker.ietf.org/doc/html/rfc8132#section-3).
    ///
    /// Not available for HTTP.
    Patch = u64::pow(2, 5),

    /// iPATCH method as specified in [RFC 8132, section 3 (CoAP)](https://datatracker.ietf.org/doc/html/rfc8132#section-3).
    ///
    /// Not available for HTTP.
    IPatch = u64::pow(2, 6),

    /// GET method as specified in [RFC 7252, section 5.8.1 (CoAP)](https://datatracker.ietf.org/doc/html/rfc7252#section-5.8.1)
    /// and [RFC 7231, section 4.3.1 (HTTP)](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.1),
    /// intended for use in [Dynamic Resource Creation](https://www.rfc-editor.org/rfc/rfc9237#section-2.3).
    DynamicGet = u64::pow(2, 32),

    /// POST method as specified in [RFC 7252, section 5.8.2 (CoAP)](https://datatracker.ietf.org/doc/html/rfc7252#section-5.8.2)
    /// and [RFC 7231, section 4.3.3 (HTTP)](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.3),
    /// intended for use in [Dynamic Resource Creation](https://www.rfc-editor.org/rfc/rfc9237#section-2.3).
    DynamicPost = u64::pow(2, 33),

    /// PUT method as specified in [RFC 7252, section 5.8.3 (CoAP)](https://datatracker.ietf.org/doc/html/rfc7252#section-5.8.3)
    /// and [RFC 7231, section 4.3.4 (HTTP)](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.4),
    /// intended for use in [Dynamic Resource Creation](https://www.rfc-editor.org/rfc/rfc9237#section-2.3).
    DynamicPut = u64::pow(2, 34),

    /// DELETE method as specified in [RFC 7252, section 5.8.4 (CoAP)](https://datatracker.ietf.org/doc/html/rfc7252#section-5.8.4)
    /// and [RFC 7231, section 4.3.5 (HTTP)](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.5),
    /// intended for use in [Dynamic Resource Creation](https://www.rfc-editor.org/rfc/rfc9237#section-2.3).
    DynamicDelete = u64::pow(2, 35),

    /// FETCH method as specified in [RFC 8132, section 2 (CoAP)](https://datatracker.ietf.org/doc/html/rfc8132#section-2),
    /// intended for use in [Dynamic Resource Creation](https://www.rfc-editor.org/rfc/rfc9237#section-2.3).
    ///
    /// Not available for HTTP.
    DynamicFetch = u64::pow(2, 36),

    /// PATCH method as specified in [RFC 8132, section 3 (CoAP)](https://datatracker.ietf.org/doc/html/rfc8132#section-3),
    /// intended for use in [Dynamic Resource Creation](https://www.rfc-editor.org/rfc/rfc9237#section-2.3).
    ///
    /// Not available for HTTP.
    DynamicPatch = u64::pow(2, 37),

    /// iPATCH method as specified in [RFC 8132, section 3 (CoAP)](https://datatracker.ietf.org/doc/html/rfc8132#section-3),
    /// intended for use in [Dynamic Resource Creation](https://www.rfc-editor.org/rfc/rfc9237#section-2.3).
    ///
    /// Not available for HTTP.
    DynamicIPatch = u64::pow(2, 38),
}

/// An element as part of an [`AifEncodedScope`], consisting of a path and a set of permissions
/// which are specified as a set of REST methods.
///
/// See [`AifEncodedScope`] for more information and a usage example.
///
/// Can also be used as the single member of a [`LibdcafEncodedScope`].
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct AifEncodedScopeElement {
    /// Identifier for the object of this scope element,
    /// given as a URI of a resource on a CoAP server.
    ///
    /// Refer to [section 2 of RFC 9237](https://www.rfc-editor.org/rfc/rfc9237#section-2)
    /// for specification details.
    pub path: String,

    /// Permissions for the object (identified by [path](AifEncodedScopeElement::path))
    /// of this scope element, given as a set of REST (CoAP or HTTP) methods.
    ///
    /// More specifically, this is a bitmask---see [`AifRestMethod`] for further explanation.
    /// Refer to [section 2 of RFC 9237](https://www.rfc-editor.org/rfc/rfc9237#section-2)
    /// for specification details.
    pub permissions: BitFlags<AifRestMethod>,
}

/// A scope encoded using the
/// [Authorization Information Format (AIF) for ACE](https://www.rfc-editor.org/rfc/rfc9237).
///
/// More specifically, this uses the specific instantiation of AIF intended for REST resources
/// which are identified by URI paths, as described in [RFC 9237, section 2.1](https://www.rfc-editor.org/rfc/rfc9237#section-2.1).
/// An AIF-encoded scope consists of [`AifEncodedScopeElement`]s, each describing a URI path
/// (the object of the scope) and a set of REST methods (the permissions of the scope).
///
/// Note that the [`libdcaf` implementation](https://gitlab.informatik.uni-bremen.de/DCAF/dcaf)
/// uses a format in which only a single [`AifEncodedScopeElement`] is used in the scope.
/// To use this format, please use the [`LibdcafEncodedScope`] instead.
///
/// # Example
/// For example, say you want to create a scope consisting of two elements:
/// - A scope for the local path `/restricted`,
///   consisting only of "read-only" methods GET and FETCH.
/// - A scope for the local path `/unrestricted`, allowing every method.
///
/// This would look like the following:
/// ```
/// # use dcaf::AifEncodedScope;
/// # use dcaf::common::scope::{AifEncodedScopeElement, AifRestMethod, AifRestMethodSet};
/// let restricted = AifEncodedScopeElement::new("restricted", AifRestMethod::Get | AifRestMethod::Fetch);
/// let unrestricted = AifEncodedScopeElement::new("unrestricted", AifRestMethodSet::all());
/// let scope = AifEncodedScope::new(vec![restricted, unrestricted]);
/// # let restricted = AifEncodedScopeElement::new("restricted", AifRestMethod::Get | AifRestMethod::Fetch);
/// # let unrestricted = AifEncodedScopeElement::new("unrestricted", AifRestMethodSet::all());
/// assert_eq!(scope.elements(), &vec![restricted, unrestricted])
/// ```
///
/// ## Encoding
/// The scope from the example above would be encoded like this (given in JSON):
/// ```json
/// [["restricted", 17], ["unrestricted", 545460846719]]
/// ```
/// As specified in [RFC 9237, section 3](https://www.rfc-editor.org/rfc/rfc9237#section-3),
/// `GET` to `iPATCH` are encoded from 2<sup>0</sup> to 2<sup>6</sup>, while the dynamic variants
/// go from 2<sup>32</sup> to 2<sup>38</sup>. This is why in `restricted`, the number equals
/// 17 (2<sup>0</sup> + 2<sup>4</sup>), and in `unrestricted` equals the sum of all these numbers.
/// [`AifRestMethod`] does the work on this (including encoding and decoding bitmasks given as
/// numbers), clients do not need to handle this themselves and can simply use its methods together
/// with the methods provided by [`AifRestMethodSet`].
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize)]
pub struct AifEncodedScope(Vec<AifEncodedScopeElement>);

/// A scope encoded using the [Authorization Information Format (AIF) for ACE](https://www.rfc-editor.org/rfc/rfc9237)
/// as in [`AifEncodedScope`], but only consisting of a single [`AifEncodedScopeElement`]
/// instead of an array of them.
///
/// This is done to provide interoperability support for the
/// [`libdcaf` implementation](https://gitlab.informatik.uni-bremen.de/DCAF/dcaf),
/// which currently uses this format to describe its scopes.
///
/// *This struct is only provided to allow compatability with the
/// [`libdcaf` implementation](https://gitlab.informatik.uni-bremen.de/DCAF/dcaf)---if you don't
/// require this, simply use the spec-compliant [`AifEncodedScope`] instead, as it provides a
/// superset of the functionality of this type.*
///
/// Refer to [`AifEncodedScope`] for details on the format, and "Difference to [`AifEncodedScope`]"
/// for details on the difference to it.
///
/// # Example
/// To create a scope allowing only the GET and FETCH methods to be called the local URI `readonly`:
/// ```
/// # use dcaf::common::scope::{AifEncodedScopeElement, AifRestMethod};
/// # use dcaf::LibdcafEncodedScope;
/// let scope = LibdcafEncodedScope::new("readonly", AifRestMethod::Get | AifRestMethod::Fetch);
/// assert_eq!(scope.element().permissions.bits(), u64::pow(2, 0) + u64::pow(2, 4));
/// ```
///
/// # Difference to [`AifEncodedScope`]
/// The only difference here is that while [`AifEncodedScope`] would encode the above example
/// like so (given as JSON):
/// ```json
/// [["readonly", 17]]
/// ```
/// [`LibdcafEncodedScope`] would encode it like so:
/// ```json
/// ["readonly", 17]
/// ```
/// Note that this implies that the latter only allows a single scope element (i.e. a single row
/// in the access matrix) to be specified, while the former allows multiple elements.
/// As mentioned in the beginning, only use this struct if you need to communicate with libdcaf,
/// use [`AifEncodedScope`] in all other cases.
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize)]
pub struct LibdcafEncodedScope(AifEncodedScopeElement);

/// Scope of an access token as specified in
/// [RFC 9200, section 5.8.1](https://www.rfc-editor.org/rfc/rfc9200#section-5.8.1-2.4).
///
/// May be used both for [AccessTokenRequest](crate::AccessTokenRequest)s and
/// [AccessTokenResponse](crate::AccessTokenResponse)s.
/// Note that you rarely need to create instances of this type for that purpose,
/// instead you can just pass in the concrete types (e.g. [TextEncodedScope], [BinaryEncodedScope])
/// directly into the builder.
///
/// # Example
///
/// You can create binary, AIF-, or text-encoded scopes:
/// ```
/// # use std::error::Error;
/// # use dcaf::common::scope::{BinaryEncodedScope, Scope, TextEncodedScope, AifEncodedScope, AifRestMethod};
/// # use dcaf::error::{InvalidTextEncodedScopeError, InvalidBinaryEncodedScopeError};
/// # #[cfg(feature = "std")] {
/// let text_scope = Scope::from(TextEncodedScope::try_from("dcaf rs")?);
/// let binary_scope = Scope::from(BinaryEncodedScope::try_from(vec![0xDC, 0xAF].as_slice())?);
/// let aif_scope = Scope::from(AifEncodedScope::from(vec![("/tmp", AifRestMethod::Get.into())]));
/// # }
/// # Ok::<(), Box<dyn Error>>(())
/// ```
///
/// For information on how to initialize a specific scope type
/// or retrieve the individual elements inside them, see their respective documentation pages.
#[derive(Debug, PartialEq, Eq, Clone, Hash, IntoStaticStr)]
pub enum Scope {
    /// Scope encoded using Text, as specified in
    /// [RFC 6749, section 1.3](https://www.rfc-editor.org/rfc/rfc6749#section-1.3).
    ///
    /// For details, see the documentation of [`TextEncodedScope`].
    ///
    /// # Example
    /// Creating a scope containing "device_alpha" and "device_beta" (note that spaces in their
    /// name wouldn't work):
    /// ```
    /// # use dcaf::common::scope::TextEncodedScope;
    /// # use dcaf::error::InvalidTextEncodedScopeError;
    /// let scope = TextEncodedScope::try_from(vec!["device_alpha", "device_beta"])?;
    /// assert_eq!(scope, TextEncodedScope::try_from("device_alpha device_beta")?);
    /// assert!(scope.elements().eq(vec!["device_alpha", "device_beta"]));
    /// assert!(TextEncodedScope::try_from(vec!["device alpha", "device beta"]).is_err());
    /// # Ok::<(), InvalidTextEncodedScopeError>(())
    /// ```
    TextEncoded(TextEncodedScope),

    /// Scope encoded using custom binary encoding.
    ///
    /// For details, see the documentation of [`BinaryEncodedScope`].
    ///
    /// # Example
    /// Creating a scope containing 0xDCAF and 0xAFDC with a separator of 0x00:
    /// ```
    /// # use dcaf::common::scope::BinaryEncodedScope;
    /// # use dcaf::error::InvalidBinaryEncodedScopeError;
    /// let scope = BinaryEncodedScope::try_from(vec![0xDC, 0xAF, 0x00, 0xAF, 0xDC].as_slice())?;
    /// assert!(scope.elements(Some(0x00))?.eq(&vec![vec![0xDC, 0xAF], vec![0xAF, 0xDC]]));
    /// assert!(scope.elements(None)?.eq(&vec![vec![0xDC, 0xAF, 0x00, 0xAF, 0xDC]]));
    /// assert!(scope.elements(Some(0xDC)).is_err());  // no separators at the beginning or end
    /// # Ok::<(), InvalidBinaryEncodedScopeError>(())
    /// ```
    BinaryEncoded(BinaryEncodedScope),

    /// Scope encoded using the [Authorization Information Format (AIF) for ACE](https://www.rfc-editor.org/rfc/rfc9237).
    ///
    /// For details, see the documentation of [`AifEncodedScope`].
    ///
    /// # Example
    /// Creating a scope containing `["/s/temp", 1]` (1 representing `GET`) and `["/a/led", 5]`
    /// (5 representing `GET` and `FETCH`):
    /// ```
    /// # use dcaf::AifEncodedScope;
    /// # use dcaf::common::scope::AifRestMethod;
    /// let scope = AifEncodedScope::from(vec![
    ///    ("/s/temp", AifRestMethod::Get.into()),
    ///    ("/a/led", AifRestMethod::Get | AifRestMethod::Fetch)
    /// ]);
    /// ```
    AifEncoded(AifEncodedScope),

    /// [`libdcaf`](https://gitlab.informatik.uni-bremen.de/DCAF/dcaf)-specific
    /// variant of [`AifEncoded`](Scope::AifEncoded) which consists of only a single
    /// [`AifEncodedScopeElement`].
    ///
    /// *Use only if trying to maintain compatibility to `libdcaf`.*
    ///
    /// For details, see the documentation of [`LibdcafEncodedScope`].
    ///
    /// # Example
    /// Creating a scope containing `["/s/temp", 1]` (1 representing `GET`):
    /// ```
    /// # use dcaf::LibdcafEncodedScope;
    /// # use dcaf::common::scope::AifRestMethod;
    /// let scope = LibdcafEncodedScope::new("/s/temp", AifRestMethod::Get.into());
    /// ```
    LibdcafEncoded(LibdcafEncodedScope),
}

/// Contains conversion methods for ACE-OAuth data types.
/// One part of this is converting enum types from and to their CBOR abbreviations in
/// [`cbor_abbreviations`](crate::constants::cbor_abbreviations),
/// another part is implementing the [`ToCborMap`](crate::ToCborMap) type for the
/// models which are represented as CBOR maps.
mod conversion {
    use ciborium::value::{Integer, Value};
    use serde::{Deserializer, Serializer};
    use serde::de::Error;

    use crate::error::{
        InvalidAifEncodedScopeError, InvalidBinaryEncodedScopeError, InvalidTextEncodedScopeError,
        ScopeFromValueError, WrongSourceTypeError,
    };

    use super::*;

    impl TextEncodedScope {
        /// Return the individual elements (i.e., access ranges) of this scope.
        ///
        /// Post-condition: The returned iterator will not be empty, and none of its elements
        /// may contain spaces (` `), double-quotes (`"`) or backslashes (`\\'`).
        ///
        /// # Example
        ///
        /// ```
        /// # use dcaf::common::scope::TextEncodedScope;
        /// # use dcaf::error::InvalidTextEncodedScopeError;
        /// let simple = TextEncodedScope::try_from("this is a test")?;
        /// assert!(simple.elements().eq(vec!["this", "is", "a", "test"]));
        /// # Ok::<(), InvalidTextEncodedScopeError>(())
        /// ```
        pub fn elements(&self) -> impl Iterator<Item = &str> {
            self.0.split(' ')
        }
    }

    impl TryFrom<&str> for TextEncodedScope {
        type Error = InvalidTextEncodedScopeError;

        fn try_from(value: &str) -> Result<Self, Self::Error> {
            if value.ends_with(' ') {
                Err(InvalidTextEncodedScopeError::EndsWithSeparator)
            } else if value.starts_with(' ') {
                Err(InvalidTextEncodedScopeError::StartsWithSeparator)
            } else if value.contains(['"', '\\']) {
                Err(InvalidTextEncodedScopeError::IllegalCharacters)
            } else if value.contains("  ") {
                Err(InvalidTextEncodedScopeError::ConsecutiveSeparators)
            } else if value.is_empty() {
                Err(InvalidTextEncodedScopeError::EmptyScope)
            } else {
                Ok(TextEncodedScope(value.into()))
            }
        }
    }

    impl TryFrom<Vec<&str>> for TextEncodedScope {
        type Error = InvalidTextEncodedScopeError;

        fn try_from(value: Vec<&str>) -> Result<Self, Self::Error> {
            if value.iter().any(|x| x.contains([' ', '\\', '"'])) {
                Err(InvalidTextEncodedScopeError::IllegalCharacters)
            } else if value.iter().any(|x| x.is_empty()) {
                Err(InvalidTextEncodedScopeError::EmptyElement)
            } else if value.is_empty() {
                Err(InvalidTextEncodedScopeError::EmptyScope)
            } else {
                // Fold the vec into a single string, using space as a separator
                Ok(TextEncodedScope(value.join(" ")))
            }
        }
    }

    impl BinaryEncodedScope {
        /// Return the individual elements (i.e., access ranges) of this scope.
        ///
        /// If no separator is given (i.e. it is `None`), it is assumed that the scope consists
        /// of a single element and will be returned as such.
        ///
        /// ## Pre-conditions
        /// - If a separator is given, it may neither be the first nor last element of the scope.
        /// - If a separator is given, it may not occur twice in a row in the scope.
        /// - The scope must not be empty.
        ///
        /// ## Post-conditions
        /// - The returned vector will not be empty.
        /// - None of its elements will be empty.
        /// - If a separator is given, none of its elements will contain it.
        /// - If no separator is given, the vector will consist of a single element, containing
        ///   the whole binary-encoded scope.
        ///
        /// # Example
        ///
        /// ```
        /// # use dcaf::common::scope::BinaryEncodedScope;
        /// # use dcaf::error::InvalidBinaryEncodedScopeError;
        /// let simple = BinaryEncodedScope::try_from(vec![0xDC, 0x21, 0xAF].as_slice())?;
        /// assert!(simple.elements(Some(0x21))?.eq(&vec![vec![0xDC], vec![0xAF]]));
        /// assert!(simple.elements(None)?.eq(&vec![vec![0xDC, 0x21, 0xAF]]));
        /// assert!(simple.elements(Some(0xDC)).is_err());
        /// # Ok::<(), InvalidBinaryEncodedScopeError>(())
        /// ```
        ///
        /// # Errors
        /// - If the binary encoded scope separated by the given `separator` is invalid in any way.
        ///   This may be the case if:
        ///   - The scope starts with a separator
        ///   - The scope ends with a separator
        ///   - The scope contains two separators in a row.
        ///
        /// # Panics
        /// If the pre-condition that the scope isn't empty is violated.
        /// This shouldn't occur, as it's an invariant of [BinaryEncodedScope].
        pub fn elements(
            &self,
            separator: Option<u8>,
        ) -> Result<Vec<&[u8]>, InvalidBinaryEncodedScopeError> {
            // We use an assert rather than an Error because the client is not expected to handle this.
            assert!(
                !self.0.is_empty(),
                "Invariant violated: Scope may not be empty"
            );
            if let Some(separator) = separator {
                let split = self.0.split(move |x| x == &separator);
                if self.0.first().filter(|x| **x != separator).is_none() {
                    Err(InvalidBinaryEncodedScopeError::StartsWithSeparator(
                        separator,
                    ))
                } else if self.0.last().filter(|x| **x != separator).is_none() {
                    Err(InvalidBinaryEncodedScopeError::EndsWithSeparator(separator))
                } else if self.0.windows(2).any(|x| x[0] == x[1] && x[1] == separator) {
                    Err(InvalidBinaryEncodedScopeError::ConsecutiveSeparators(
                        separator,
                    ))
                } else {
                    debug_assert!(
                        split.clone().all(|x| !x.is_empty()),
                        "Post-condition violated: Result may not contain empty slices"
                    );
                    Ok(split.collect())
                }
            } else {
                // no separator given
                Ok(vec![self.0.as_slice()])
            }
        }
    }

    impl TryFrom<&[u8]> for BinaryEncodedScope {
        type Error = InvalidBinaryEncodedScopeError;

        fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
            let vec = value.to_vec();
            if vec.is_empty() {
                Err(InvalidBinaryEncodedScopeError::EmptyScope)
            } else {
                Ok(BinaryEncodedScope(vec))
            }
        }
    }

    impl AifEncodedScopeElement {
        /// Creates a new [`AifEncodedScopeElement`] over the given `path` and `permissions`.
        ///
        /// # Example
        /// Let's take the example given in Table 2 of [the RFC](https://www.rfc-editor.org/rfc/rfc9237#table-2):
        /// ```text
        ///   +================+===================================+
        ///   | URI-local-part | Permission Set                    |
        ///   +================+===================================+
        ///   | /a/make-coffee | POST, Dynamic-GET, Dynamic-DELETE |
        ///   +----------------+-----------------------------------+
        /// ```
        ///
        /// We could create an `AifEncodedScopeElement` from that data like this:
        /// (the `make_bitflags` macro is used for better readability, but is not required)
        /// ```
        /// # use enumflags2::make_bitflags;
        /// use dcaf::common::scope::{AifEncodedScopeElement, AifRestMethod};
        /// let element = AifEncodedScopeElement::new(
        ///    "/a/make-coffee", make_bitflags!(AifRestMethod::{Post | DynamicGet | DynamicDelete})
        /// );
        /// ```
        #[must_use]
        pub fn new<T, U>(path: T, permissions: U) -> AifEncodedScopeElement
        where
            T: Into<String>,
            U: Into<BitFlags<AifRestMethod>>,
        {
            AifEncodedScopeElement {
                path: path.into(),
                permissions: permissions.into(),
            }
        }

        /// Tries to create a new [`AifEncodedScopeElement`] from the given `path` and `permissions`.
        ///
        /// `permissions` must be a valid bitmask of REST methods, as defined in
        /// [section 3 of RFC 9237](https://www.rfc-editor.org/rfc/rfc9237#section-3).
        ///
        /// # Errors
        /// If the given `permissions` do not correspond to a valid set of [`AifRestMethod`]s
        /// as defined in
        /// [section 3 of RFC 9237](https://www.rfc-editor.org/rfc/rfc9237#section-3).
        ///
        /// # Example
        /// For example, say we want to encode `["/a/led", 5]`, where the 5 corresponds to
        /// `GET` and `FETCH` (due to 2<sup>0</sup> and 2<sup>4</sup>):
        /// ```
        /// # use dcaf::common::scope::{AifEncodedScopeElement, AifRestMethod};
        /// # use dcaf::error::InvalidAifEncodedScopeError;
        /// let element = AifEncodedScopeElement::try_from_bits("/a/led", 5)?;
        /// assert_eq!(element, AifEncodedScopeElement::new("/a/led", AifRestMethod::Get | AifRestMethod::Put));
        /// # Ok::<(), InvalidAifEncodedScopeError>(())
        /// ```
        /// This method returns a result because it's possible to specify a bitmask that doesn't
        /// represent a REST method (such as 2<sup>31</sup>):
        /// ```
        /// # use dcaf::common::scope::{AifEncodedScopeElement};
        /// assert!(AifEncodedScopeElement::try_from_bits("no", u64::pow(2, 31)).is_err());
        /// ```
        pub fn try_from_bits<T>(
            path: T,
            permissions: u64,
        ) -> Result<AifEncodedScopeElement, InvalidAifEncodedScopeError>
        where
            T: Into<String>,
        {
            BitFlags::<AifRestMethod>::from_bits(permissions)
                .map_err(|_| InvalidAifEncodedScopeError::InvalidRestMethodSet)
                .map(|permissions| AifEncodedScopeElement {
                    path: path.into(),
                    permissions,
                })
        }

        /// Turns itself into a [`Value`].
        fn into_cbor_value(self) -> Value {
            Value::Array(vec![
                Value::Text(self.path),
                Value::Integer(Integer::from(self.permissions.bits())),
            ])
        }
    }

    impl AifEncodedScope {
        /// Creates a new [`AifEncodedScope`] consisting of the given `elements`.
        #[must_use]
        pub fn new(elements: Vec<AifEncodedScopeElement>) -> AifEncodedScope {
            AifEncodedScope(elements)
        }

        /// Returns a reference to the [`AifEncodedScopeElement`]s of this scope.
        ///
        /// # Example
        /// ```
        /// # use dcaf::AifEncodedScope;
        /// # use dcaf::common::scope::{AifEncodedScopeElement, AifRestMethod, AifRestMethodSet};
        /// let first = AifEncodedScopeElement::new("first", AifRestMethodSet::empty());
        /// let second = AifEncodedScopeElement::new("second", AifRestMethod::Patch);
        /// // We only clone here for the assert call below. This is usually not required.
        /// let scope = AifEncodedScope::new(vec![first.clone(), second.clone()]);
        /// assert_eq!(scope.elements(), &vec![first, second]);
        /// ```
        #[must_use]
        pub fn elements(&self) -> &Vec<AifEncodedScopeElement> {
            &self.0
        }

        /// Returns the [`AifEncodedScopeElement`]s of this scope.
        ///
        /// # Example
        /// ```
        /// # use dcaf::AifEncodedScope;
        /// # use dcaf::common::scope::{AifEncodedScopeElement, AifRestMethod, AifRestMethodSet};
        /// let first = AifEncodedScopeElement::new("first", AifRestMethodSet::empty());
        /// let second = AifEncodedScopeElement::new("second", AifRestMethod::Patch);
        /// // We only clone here for the assert call below. This is usually not required.
        /// let scope = AifEncodedScope::new(vec![first.clone(), second.clone()]);
        /// assert_eq!(scope.to_elements(), vec![first, second]);
        /// ```
        #[must_use]
        pub fn to_elements(self) -> Vec<AifEncodedScopeElement> {
            self.0
        }
    }

    impl Serialize for AifEncodedScopeElement {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Value::Array(vec![
                Value::Text(self.path.clone()),
                Value::Integer(Integer::from(self.permissions.bits())),
            ])
            .serialize(serializer)
        }
    }

    impl<T> From<Vec<(T, BitFlags<AifRestMethod>)>> for AifEncodedScope
    where
        T: Into<String>,
    {
        fn from(value: Vec<(T, BitFlags<AifRestMethod>)>) -> Self {
            AifEncodedScope::new(
                value
                    .into_iter()
                    .map(|(path, set)| AifEncodedScopeElement::new(path, set))
                    .collect(),
            )
        }
    }

    impl TryFrom<Vec<(String, u64)>> for AifEncodedScope {
        type Error = InvalidAifEncodedScopeError;

        fn try_from(value: Vec<(String, u64)>) -> Result<Self, Self::Error> {
            Ok(AifEncodedScope::new(
                value
                    .into_iter()
                    .map(|(path, rest)| AifEncodedScopeElement::try_from_bits(path, rest))
                    .collect::<Result<Vec<AifEncodedScopeElement>, InvalidAifEncodedScopeError>>(
                    )?,
            ))
        }
    }

    impl LibdcafEncodedScope {
        /// Creates a new libdcaf-encoded scope from the given `path` and `permissions`.
        ///
        /// Refer to [`AifEncodedScopeElement::new`] for details and
        /// an example applicable to this method.
        #[must_use]
        pub fn new<T>(path: T, permissions: BitFlags<AifRestMethod>) -> LibdcafEncodedScope
        where
            T: Into<String>,
        {
            LibdcafEncodedScope(AifEncodedScopeElement::new(path, permissions))
        }

        /// Creates a new libdcaf-encoded scope from the given `element`.
        ///
        /// Refer to [`AifEncodedScopeElement`] and [`LibdcafEncodedScope`] for details.
        #[must_use]
        pub fn from_element(element: AifEncodedScopeElement) -> LibdcafEncodedScope {
            LibdcafEncodedScope(element)
        }

        /// Tries to create a new libdcaf-encoded scope from the given `path` and `permissions`.
        ///
        /// The given `permissions` must be a valid bitmask of the allowed REST methods,
        /// as defined in [section 3 of RFC 9237](https://www.rfc-editor.org/rfc/rfc9237#section-3).
        ///
        /// # Errors
        /// Refer to [`AifEncodedScopeElement::try_from_bits`].
        ///
        /// # Example
        /// Refer to [`AifEncodedScopeElement::try_from_bits`].
        pub fn try_from_bits<T>(
            path: T,
            permissions: u64,
        ) -> Result<LibdcafEncodedScope, InvalidAifEncodedScopeError>
        where
            T: Into<String>,
        {
            Ok(LibdcafEncodedScope::from_element(
                AifEncodedScopeElement::try_from_bits(path, permissions)?,
            ))
        }

        /// Returns a reference to the single element contained in this scope.
        #[must_use]
        pub fn element(&self) -> &AifEncodedScopeElement {
            &self.0
        }

        /// Returns the single element contained in this scope.
        #[must_use]
        pub fn to_element(self) -> AifEncodedScopeElement {
            self.0
        }

        /// Returns a vector of a reference to the single element in this scope.
        #[must_use]
        pub fn elements(&self) -> Vec<&AifEncodedScopeElement> {
            vec![self.element()]
        }

        /// Returns a vector of the single element in this scope.
        #[must_use]
        pub fn to_elements(self) -> Vec<AifEncodedScopeElement> {
            vec![self.to_element()]
        }
    }

    impl From<LibdcafEncodedScope> for Scope {
        fn from(value: LibdcafEncodedScope) -> Self {
            Scope::LibdcafEncoded(value)
        }
    }

    impl From<AifEncodedScope> for Scope {
        fn from(value: AifEncodedScope) -> Self {
            Scope::AifEncoded(value)
        }
    }

    impl From<TextEncodedScope> for Scope {
        fn from(value: TextEncodedScope) -> Self {
            Scope::TextEncoded(value)
        }
    }

    impl From<BinaryEncodedScope> for Scope {
        fn from(value: BinaryEncodedScope) -> Self {
            Scope::BinaryEncoded(value)
        }
    }

    impl TryFrom<Vec<&str>> for Scope {
        type Error = InvalidTextEncodedScopeError;

        fn try_from(value: Vec<&str>) -> Result<Self, InvalidTextEncodedScopeError> {
            Ok(Scope::from(TextEncodedScope::try_from(value)?))
        }
    }

    impl TryFrom<&[u8]> for Scope {
        type Error = InvalidBinaryEncodedScopeError;

        fn try_from(value: &[u8]) -> Result<Self, InvalidBinaryEncodedScopeError> {
            Ok(Scope::from(BinaryEncodedScope::try_from(value)?))
        }
    }

    impl TryFrom<Vec<(String, u64)>> for Scope {
        type Error = InvalidAifEncodedScopeError;

        fn try_from(value: Vec<(String, u64)>) -> Result<Self, Self::Error> {
            Ok(Scope::from(AifEncodedScope::try_from(value)?))
        }
    }

    impl TryFrom<Scope> for BinaryEncodedScope {
        type Error = WrongSourceTypeError<Scope>;

        fn try_from(value: Scope) -> Result<Self, Self::Error> {
            if let Scope::BinaryEncoded(scope) = value {
                Ok(scope)
            } else {
                Err(WrongSourceTypeError::new("BinaryEncoded", value.into()))
            }
        }
    }

    impl TryFrom<Scope> for TextEncodedScope {
        type Error = WrongSourceTypeError<Scope>;

        fn try_from(value: Scope) -> Result<Self, Self::Error> {
            if let Scope::TextEncoded(scope) = value {
                Ok(scope)
            } else {
                Err(WrongSourceTypeError::new("TextEncoded", value.into()))
            }
        }
    }

    impl TryFrom<Scope> for AifEncodedScope {
        type Error = WrongSourceTypeError<Scope>;

        fn try_from(value: Scope) -> Result<Self, Self::Error> {
            if let Scope::AifEncoded(scope) = value {
                Ok(scope)
            } else {
                Err(WrongSourceTypeError::new("AifEncoded", value.into()))
            }
        }
    }

    impl TryFrom<Scope> for LibdcafEncodedScope {
        type Error = WrongSourceTypeError<Scope>;

        fn try_from(value: Scope) -> Result<Self, Self::Error> {
            if let Scope::LibdcafEncoded(scope) = value {
                Ok(scope)
            } else {
                Err(WrongSourceTypeError::new("LibdcafEncoded", value.into()))
            }
        }
    }

    impl From<Scope> for Value {
        fn from(scope: Scope) -> Self {
            match scope {
                Scope::TextEncoded(text) => Value::Text(text.0),
                Scope::BinaryEncoded(binary) => Value::Bytes(binary.0),
                Scope::AifEncoded(aif) => Value::Array(
                    aif.to_elements()
                        .into_iter()
                        .map(AifEncodedScopeElement::into_cbor_value)
                        .collect(),
                ),
                Scope::LibdcafEncoded(lib) => lib.0.into_cbor_value(),
            }
        }
    }

    impl TryFrom<Value> for Scope {
        type Error = ScopeFromValueError;

        fn try_from(value: Value) -> Result<Self, Self::Error> {
            #[allow(clippy::needless_pass_by_value)] // makes it easier to use later on
            fn value_to_aif_element(
                value: Value,
            ) -> Result<AifEncodedScopeElement, InvalidAifEncodedScopeError> {
                let values = value
                    .as_array()
                    .ok_or(InvalidAifEncodedScopeError::MalformedArray)?;
                let path = values
                    .first()
                    .and_then(Value::as_text)
                    .ok_or(InvalidAifEncodedScopeError::MalformedArray)?
                    .to_string();
                let permissions = values
                    .get(1)
                    .and_then(|x| {
                        x.as_integer().map(|x| {
                            u64::try_from(x)
                                .map(BitFlags::<AifRestMethod>::from_bits)
                                .map(Result::ok)
                                .ok()
                        })
                    })
                    .flatten()
                    .flatten() // better than ???, I guess
                    .ok_or(InvalidAifEncodedScopeError::MalformedArray)?;
                Ok(AifEncodedScopeElement::new(path, permissions))
            }

            match value {
                Value::Bytes(b) => Ok(Scope::BinaryEncoded(BinaryEncodedScope::try_from(
                    b.as_slice(),
                )?)),
                Value::Text(t) => Ok(Scope::TextEncoded(TextEncodedScope::try_from(t.as_str())?)),
                Value::Array(a) => {
                    if a.first().filter(|x| x.is_text()).is_some() {
                        // Special handling for libdcaf
                        Ok(Scope::LibdcafEncoded(LibdcafEncodedScope(
                            value_to_aif_element(Value::Array(a))?,
                        )))
                    } else {
                        a.into_iter()
                            .map(value_to_aif_element)
                            .collect::<Result<Vec<AifEncodedScopeElement>, InvalidAifEncodedScopeError>>()
                            .map(|x| Scope::AifEncoded(AifEncodedScope::new(x)))
                            .map_err(ScopeFromValueError::InvalidAifEncodedScope)
                    }
                }
                v => Err(ScopeFromValueError::invalid_type(&v)),
            }
        }
    }

    impl Serialize for Scope {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Value::from(self.clone()).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Scope {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            Scope::try_from(Value::deserialize(deserializer)?)
                .map_err(|x| D::Error::custom(x.to_string()))
        }
    }
}
