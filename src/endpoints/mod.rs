//! Contains CBOR-serializable data types for the endpoints of ACE-OAuth.
//!
//! These endpoints are described in section 5 of
//! [`draft-ietf-ace-oauth-authz`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html).
//!
//! # Layout
//! - [`creation_hint`]: Contains the data model for Authorization Server Request Creation Hints.
//! - [`token_req`]: Contains the data models for structures related to access token requests and responses.

pub mod creation_hint;
pub mod token_req;

